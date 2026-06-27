use std::sync::Arc;

use super::compact::{
    apply_emergency_compaction_fallback,
    is_context_overflow_error,
    prune_orphan_tool_outputs,
    response_input_from_core_items,
    sanitize_items_for_compact,
    send_compaction_checkpoint_warning,
};
use super::Session;
use super::TurnContext;
use crate::Prompt;
use crate::error::CodexErr;
use crate::error::Result as CodexResult;
use crate::error::RetryAfter;
use crate::protocol::AgentMessageEvent;
use crate::protocol::ErrorEvent;
use crate::protocol::EventMsg;
use crate::protocol::InputItem;
use code_protocol::models::ResponseInputItem;
use code_protocol::models::ResponseItem;
use code_protocol::protocol::CompactedItem;
use code_protocol::protocol::RolloutItem;
use crate::util::backoff;
use reqwest::StatusCode;
use std::time::Duration;

const MAX_REMOTE_COMPACT_CONTEXT_OVERFLOW_TRIMS: usize = 32;
const MAX_REMOTE_COMPACT_USAGE_LIMIT_RETRIES: usize = 2;

fn prepare_missing_item_retry(
    err: &CodexErr,
    turn_items: &mut [ResponseItem],
    already_retried: bool,
) -> Option<usize> {
    if already_retried || !is_missing_compact_item_error(err) {
        return None;
    }
    let stripped = strip_response_item_ids(turn_items);
    (stripped > 0).then_some(stripped)
}

fn is_missing_compact_item_error(err: &CodexErr) -> bool {
    let CodexErr::UnexpectedStatus(resp) = err else {
        return false;
    };
    if resp.status != StatusCode::NOT_FOUND {
        return false;
    }
    let body = resp.body.to_ascii_lowercase();
    body.contains("previous_response_not_found")
        || body.contains("item_not_found")
        || ((body.contains("not found") || body.contains("missing"))
            && (body.contains("rs_")
                || body.contains("msg_")
                || body.contains("fc_")
                || body.contains("item")))
}

fn strip_response_item_ids(items: &mut [ResponseItem]) -> usize {
    let mut stripped = 0usize;
    for item in items {
        let id = match item {
            ResponseItem::AdditionalTools { id, .. }
            | ResponseItem::Reasoning { id, .. }
            | ResponseItem::Message { id, .. }
            | ResponseItem::WebSearchCall { id, .. }
            | ResponseItem::FunctionCall { id, .. }
            | ResponseItem::LocalShellCall { id, .. }
            | ResponseItem::ToolSearchCall { id, .. }
            | ResponseItem::CustomToolCall { id, .. } => id,
            ResponseItem::ImageGenerationCall { .. }
            | ResponseItem::FunctionCallOutput { .. }
            | ResponseItem::ToolSearchOutput { .. }
            | ResponseItem::CustomToolCallOutput { .. }
            | ResponseItem::CompactionSummary { .. }
            | ResponseItem::ContextCompaction { .. }
            | ResponseItem::GhostSnapshot { .. }
            | ResponseItem::Other => continue,
        };
        if id.take().is_some() {
            stripped = stripped.saturating_add(1);
        }
    }
    stripped
}

pub(super) async fn run_inline_remote_auto_compact_task(
    sess: Arc<Session>,
    turn_context: Arc<TurnContext>,
    extra_input: Vec<InputItem>,
) -> Vec<ResponseItem> {
    let sub_id = sess.next_internal_sub_id();
    match run_remote_compact_task_inner(&sess, &turn_context, &sub_id, extra_input).await {
        Ok(history) => history,
        Err(err) => {
            let event = sess.make_event(
                &sub_id,
                EventMsg::Error(ErrorEvent {
                    message: format!("remote compact failed: {err}"),
                }),
            );
            sess.send_event(event).await;
            Vec::new()
        }
    }
}

pub(super) async fn run_remote_compact_task(
    sess: Arc<Session>,
    turn_context: Arc<TurnContext>,
    sub_id: String,
    extra_input: Vec<InputItem>,
) -> CodexResult<()> {
    match run_remote_compact_task_inner(&sess, &turn_context, &sub_id, extra_input).await {
        Ok(_history) => {
            // Mirror local compaction behaviour: clear the running task when the
            // compaction finished successfully so the UI can unblock.
            sess.remove_task(&sub_id);
            Ok(())
        }
        Err(err) => {
            let event = sess.make_event(
                &sub_id,
                EventMsg::Error(ErrorEvent {
                    message: err.to_string(),
                }),
            );
            sess.send_event(event).await;
            Err(err)
        }
    }
}

async fn run_remote_compact_task_inner(
    sess: &Arc<Session>,
    turn_context: &Arc<TurnContext>,
    sub_id: &str,
    extra_input: Vec<InputItem>,
) -> CodexResult<Vec<ResponseItem>> {
    let mut turn_items = sess.turn_input_with_history({
        if extra_input.is_empty() {
            Vec::new()
        } else {
            let response_input: ResponseInputItem = response_input_from_core_items(extra_input);
            vec![ResponseItem::from(response_input)]
        }
    });

    turn_items = sanitize_items_for_compact(turn_items);
    let mut truncated_count = 0usize;
    let max_retries = turn_context.client.get_provider().stream_max_retries();
    let mut retries = 0;
    let mut usage_limit_retries = 0usize;
    let mut retried_missing_items_without_ids = false;
    let new_history = loop {
        prune_orphan_tool_outputs(&mut turn_items);

        let mut prompt = Prompt::default();
        prompt.input = turn_items.clone();
        prompt.store = !sess.disable_response_storage;
        prompt.base_instructions_override = turn_context.base_instructions.clone();
        prompt.include_additional_instructions = false;
        prompt.log_tag = Some("codex/remote-compact".to_string());

        let _used_fallback_model_metadata = sess.apply_remote_model_overrides(&mut prompt).await;

        match turn_context
            .client
            .compact_conversation_history(&prompt)
            .await
        {
            Ok(history) => {
                if truncated_count > 0 {
                    tracing::warn!(
                        "Context window exceeded during remote compact; trimmed {truncated_count} item(s) from prompt"
                    );
                }
                break history;
            }
            Err(err) if is_context_overflow_error(&err) => {
                if turn_items.len() > 1
                    && truncated_count < MAX_REMOTE_COMPACT_CONTEXT_OVERFLOW_TRIMS
                {
                    tracing::warn!(
                        "Context window exceeded while remote compacting; dropping oldest item ({} remaining)",
                        turn_items.len().saturating_sub(1)
                    );
                    turn_items.remove(0);
                    truncated_count = truncated_count.saturating_add(1);
                    retries = 0;
                    usage_limit_retries = 0;
                    continue;
                }

                if truncated_count >= MAX_REMOTE_COMPACT_CONTEXT_OVERFLOW_TRIMS {
                    let reason = format!(
                        "Remote compact trimmed {truncated_count} items but still exceeded the context window."
                    );
                    return Ok(
                        apply_emergency_compaction_fallback(
                            sess,
                            turn_context.as_ref(),
                            sub_id,
                            &reason,
                        )
                        .await,
                    );
                }

                let reason = "Remote compact failed: context overflow even with minimal input.";
                return Ok(
                    apply_emergency_compaction_fallback(
                        sess,
                        turn_context.as_ref(),
                        sub_id,
                        reason,
                    )
                    .await,
                );
            }
            Err(CodexErr::UsageLimitReached(limit_err)) => {
                if usage_limit_retries >= MAX_REMOTE_COMPACT_USAGE_LIMIT_RETRIES {
                    let reason = "Remote compact hit persistent usage limits and cannot continue.";
                    return Ok(
                        apply_emergency_compaction_fallback(
                            sess,
                            turn_context.as_ref(),
                            sub_id,
                            reason,
                        )
                        .await,
                    );
                }
                usage_limit_retries = usage_limit_retries.saturating_add(1);
                let now = chrono::Utc::now();
                let retry_after = limit_err
                    .retry_after(now)
                    .unwrap_or_else(|| RetryAfter::from_duration(Duration::from_secs(5 * 60), now));
                let mut message = format!("{limit_err} Auto-retrying");
                message.push('…');
                sess.notify_stream_error(sub_id, message).await;
                tokio::time::sleep(retry_after.delay).await;
                retries = 0;
                continue;
            }
            Err(err) => {
                if let Some(stripped) = prepare_missing_item_retry(
                    &err,
                    &mut turn_items,
                    retried_missing_items_without_ids,
                ) {
                    retried_missing_items_without_ids = true;
                    retries = 0;
                    usage_limit_retries = 0;
                    tracing::warn!(
                        "remote compact referenced missing response item; stripped {stripped} item id(s) and retrying with inline transcript"
                    );
                    sess
                        .notify_stream_error(
                            sub_id,
                            "remote compact referenced missing response items; retrying with inline transcript…"
                                .to_string(),
                        )
                        .await;
                    continue;
                }
                if retries < max_retries {
                    retries += 1;
                    let delay = backoff(retries);
                    sess
                        .notify_stream_error(
                            sub_id,
                            format!(
                                "remote compact error: {err}; retrying {retries}/{max_retries} in {delay:?}…"
                            ),
                        )
                        .await;
                    tokio::time::sleep(delay).await;
                    continue;
                }

                return Err(err);
            }
        }
    };

    sess.replace_history(new_history.clone());
    {
        let mut state = sess.state.lock().unwrap();
        state.token_usage_info = None;
    }

    send_compaction_checkpoint_warning(sess, sub_id).await;

    let rollout_item = RolloutItem::Compacted(CompactedItem {
        message: "Conversation history compacted.".to_string(),
        replacement_history: None,
    });
    sess.persist_rollout_items(&[rollout_item]).await;

    let event = sess.make_event(
        sub_id,
        EventMsg::AgentMessage(AgentMessageEvent {
            message: "Compact task completed".to_string(),
        }),
    );
    sess.send_event(event).await;

    Ok(new_history)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::UnexpectedResponseError;
    use code_protocol::models::ContentItem;
    use reqwest::StatusCode;

    fn missing_item_error() -> CodexErr {
        CodexErr::UnexpectedStatus(UnexpectedResponseError {
            status: StatusCode::NOT_FOUND,
            body: r#"{"error":{"code":"previous_response_not_found","message":"Item rs_123 was not found"}}"#
                .to_string(),
            request_id: None,
        })
    }

    #[test]
    fn missing_item_retry_strips_ids_once_and_never_retries_unchanged_payload() {
        let mut turn_items = vec![
            ResponseItem::Message {
                id: Some("msg_123".to_string()),
                role: "assistant".to_string(),
                content: vec![ContentItem::OutputText {
                    text: "assistant text".to_string(),
                }],
                end_turn: None,
                phase: None,
            },
            ResponseItem::Reasoning {
                id: Some("rs_123".to_string()),
                summary: Vec::new(),
                content: None,
                encrypted_content: Some("encrypted".to_string()),
            },
            ResponseItem::FunctionCall {
                id: Some("fc_123".to_string()),
                name: "shell".to_string(),
                namespace: None,
                arguments: "{}".to_string(),
                call_id: "call_123".to_string(),
            },
        ];
        let before_retry = serde_json::to_string(&turn_items).expect("serialize before retry");

        let stripped =
            prepare_missing_item_retry(&missing_item_error(), &mut turn_items, false);

        assert_eq!(stripped, Some(3));
        let after_retry = serde_json::to_string(&turn_items).expect("serialize after retry");
        assert_ne!(
            before_retry, after_retry,
            "missing-item retry must not resend an unchanged invalid payload"
        );
        assert!(
            !after_retry.contains("\"id\""),
            "missing-item retry should inline items without server ids: {after_retry}"
        );
        assert_eq!(
            prepare_missing_item_retry(&missing_item_error(), &mut turn_items, true),
            None,
            "missing-item fallback should be one-shot"
        );
    }
}
