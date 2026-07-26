//! CDP wire protocol: framing, command/response pairing, and event delivery.
//!
//! This layer knows about `id` / `method` / `result` / `error`. It does not know what
//! any particular domain means — page state and resource interception live in
//! [`crate::runtime`].

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};

use crate::platform::{LaunchedApp, PipeTransport};
use crate::trace;

pub(crate) const COMMAND_TIMEOUT: Duration = Duration::from_secs(20);
pub(crate) const STARTUP_AUTO_ATTACH_ID: u32 = 1;

/// The first frame is written into the pipe before the app starts, so auto-attach is
/// armed before any target can execute.
pub(crate) fn startup_auto_attach_frame() -> Vec<u8> {
    let mut frame = json!({
        "id": STARTUP_AUTO_ATTACH_ID,
        "method": "Target.setAutoAttach",
        "params": {
            "autoAttach": true,
            "waitForDebuggerOnStart": true,
            "flatten": true
        }
    })
    .to_string()
    .into_bytes();
    frame.push(0);
    frame
}

#[derive(Debug)]
pub(crate) struct CdpCommandError {
    method: String,
    details: Value,
}

impl CdpCommandError {
    pub(crate) fn method(&self) -> &str {
        &self.method
    }

    pub(crate) fn details(&self) -> &Value {
        &self.details
    }
}

impl fmt::Display for CdpCommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "CDP {} failed: {}", self.method, self.details)
    }
}

impl std::error::Error for CdpCommandError {}

/// Unwraps a CDP response, which must carry exactly one of `result` or `error`.
pub(crate) fn response_result(value: Value, method: &str) -> Result<Value> {
    let Value::Object(mut response) = value else {
        bail!("CDP {method} returned a malformed response");
    };
    match (response.remove("result"), response.remove("error")) {
        (Some(result), None) => Ok(result),
        (None, Some(details)) => Err(CdpCommandError {
            method: method.to_owned(),
            details,
        }
        .into()),
        _ => bail!("CDP {method} returned a malformed response"),
    }
}

/// The CDP wire connection: framing, id bookkeeping, and event delivery.
pub(crate) struct Connection {
    app: LaunchedApp,
    transport: PipeTransport,
    next_id: u32,
    pending_responses: BTreeMap<u32, Value>,
    pending_events: VecDeque<Value>,
    handling_event: bool,
}

/// What a [`Connection`] calls back into while it waits for a command response.
pub(crate) trait SessionHandler {
    /// Handles one CDP event. `cdp` is the connection that produced it, so a handler
    /// may keep issuing commands — which re-enters [`Connection::wait_response`].
    fn handle_event(&mut self, cdp: &mut Connection, event: Value) -> Result<()>;

    /// Lets the handler shorten how long the connection blocks on the transport.
    fn wait_deadline(&self, command_deadline: Instant) -> Instant {
        command_deadline
    }

    /// Services a deadline returned earlier by [`Self::wait_deadline`]. Returning success
    /// must clear or advance that deadline; otherwise the connection would immediately
    /// call this method again.
    fn handle_wait_deadline(&mut self, app: &LaunchedApp) -> Result<()>;
}

#[derive(Debug, Eq, PartialEq)]
enum ResponseWait {
    Handler(Instant),
    Command(Instant),
}

fn response_wait(
    handler_deadline: Instant,
    command_deadline: Instant,
    now: Instant,
) -> Option<ResponseWait> {
    if handler_deadline >= command_deadline {
        Some(ResponseWait::Command(command_deadline))
    } else if handler_deadline <= now {
        None
    } else {
        Some(ResponseWait::Handler(handler_deadline))
    }
}

fn wait_for_response_message<T>(
    handler_deadline: Instant,
    command_deadline: Instant,
    now: Instant,
    mut read: impl FnMut(ResponseWait) -> Result<Option<T>>,
    handle_deadline: impl FnOnce() -> Result<()>,
) -> Result<Option<T>> {
    match response_wait(handler_deadline, command_deadline, now) {
        None => {
            handle_deadline()?;
            Ok(None)
        }
        Some(wait @ ResponseWait::Handler(_)) => match read(wait)? {
            Some(message) => Ok(Some(message)),
            None => {
                handle_deadline()?;
                Ok(None)
            }
        },
        Some(wait @ ResponseWait::Command(_)) => match read(wait)? {
            Some(message) => Ok(Some(message)),
            None => bail!("command wait ended without a response"),
        },
    }
}

impl Connection {
    pub(crate) fn new(app: LaunchedApp, transport: PipeTransport) -> Self {
        Self {
            app,
            transport,
            next_id: STARTUP_AUTO_ATTACH_ID + 1,
            pending_responses: BTreeMap::new(),
            pending_events: VecDeque::new(),
            handling_event: false,
        }
    }

    pub(crate) fn app(&self) -> &LaunchedApp {
        &self.app
    }

    /// Events received while a handler was running, not yet delivered.
    pub(crate) fn queued_events(&self) -> impl Iterator<Item = &Value> {
        self.pending_events.iter()
    }

    /// Sends a command and waits for its response. May re-enter `handler`.
    ///
    /// `handler` comes last so a caller can pass `self` alongside a shared borrow of
    /// its own fields: arguments evaluate left to right, so the shared borrow is
    /// finished before the `&mut` one is taken.
    pub(crate) fn send_command(
        &mut self,
        method: &str,
        params: Option<Value>,
        session_id: Option<&str>,
        handler: &mut dyn SessionHandler,
    ) -> Result<Value> {
        let id = self.start_command(method, params, session_id)?;
        self.wait_response(id, method, handler)
    }

    /// Sends a command without waiting. Never re-enters a handler.
    pub(crate) fn start_command(
        &mut self,
        method: &str,
        params: Option<Value>,
        session_id: Option<&str>,
    ) -> Result<u32> {
        let id = self.next_id;
        self.next_id += 1;

        let mut object = Map::new();
        object.insert("id".to_owned(), Value::from(id));
        object.insert("method".to_owned(), Value::from(method));
        if let Some(params) = params {
            object.insert("params".to_owned(), params);
        }
        if let Some(session_id) = session_id {
            object.insert("sessionId".to_owned(), Value::from(session_id));
        }

        trace(format_args!(
            "CDP_SEND id={id} method={method} session={}",
            session_id.unwrap_or("")
        ));
        self.transport
            .send(&self.app, Value::Object(object).to_string())?;
        Ok(id)
    }

    /// Waits for one response id. Events that arrive meanwhile are delivered
    /// immediately, or queued when a handler is already running.
    pub(crate) fn wait_response(
        &mut self,
        id: u32,
        method: &str,
        handler: &mut dyn SessionHandler,
    ) -> Result<Value> {
        let command_deadline = Instant::now() + COMMAND_TIMEOUT;
        loop {
            if let Some(value) = self.pending_responses.remove(&id) {
                return response_result(value, method);
            }
            if !self.handling_event
                && let Some(value) = self.pending_events.pop_front()
            {
                self.dispatch_event(value, &mut *handler)?;
                continue;
            }

            let handler_deadline = handler.wait_deadline(command_deadline);
            let app = &self.app;
            let transport = &mut self.transport;
            let message = wait_for_response_message(
                handler_deadline,
                command_deadline,
                Instant::now(),
                |wait| match wait {
                    ResponseWait::Handler(deadline) => {
                        transport.next_message_optional(app, deadline)
                    }
                    ResponseWait::Command(deadline) => transport
                        .next_message(app, deadline)
                        .with_context(|| format!("waiting for CDP response {method}#{id}"))
                        .map(Some),
                },
                || handler.handle_wait_deadline(app),
            )?;
            let Some(message) = message else {
                continue;
            };
            let value: Value = serde_json::from_str(&message).context("parse CDP message")?;
            if let Some(response_id) = value.get("id").and_then(Value::as_u64) {
                trace(format_args!(
                    "CDP_RECV_RESPONSE id={response_id} waiting={id}"
                ));
                if response_id == id as u64 {
                    return response_result(value, method);
                }
                if let Ok(response_id) = u32::try_from(response_id) {
                    self.pending_responses.insert(response_id, value);
                }
                continue;
            }
            if self.handling_event {
                self.pending_events.push_back(value);
            } else {
                self.dispatch_event(value, &mut *handler)?;
            }
        }
    }

    /// Takes the next event, from the queue or the transport. Never re-enters a handler.
    fn next_event_optional(&mut self, deadline: Instant) -> Result<Option<Value>> {
        if let Some(value) = self.pending_events.pop_front() {
            return Ok(Some(value));
        }

        loop {
            let Some(message) = self.transport.next_message_optional(&self.app, deadline)? else {
                return Ok(None);
            };
            let value: Value = serde_json::from_str(&message).context("parse CDP message")?;
            let Some(response_id) = value.get("id").and_then(Value::as_u64) else {
                return Ok(Some(value));
            };
            if let Ok(response_id) = u32::try_from(response_id) {
                self.pending_responses.insert(response_id, value);
            }
        }
    }

    /// Waits up to `deadline` for one event and delivers it. Returns without calling
    /// the handler if nothing arrives in time.
    pub(crate) fn pump_event(
        &mut self,
        deadline: Instant,
        handler: &mut dyn SessionHandler,
    ) -> Result<()> {
        match self.next_event_optional(deadline)? {
            Some(value) => self.dispatch_event(value, handler),
            None => Ok(()),
        }
    }

    /// Delivers one event. While the handler runs, further events are queued rather
    /// than nested, so a handler never observes an event from inside another event.
    fn dispatch_event(&mut self, value: Value, handler: &mut dyn SessionHandler) -> Result<()> {
        debug_assert!(!self.handling_event);
        self.handling_event = true;
        let result = handler.handle_event(self, value);
        self.handling_event = false;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinguishes_handler_wakeups_from_command_timeouts() {
        let now = Instant::now();
        let handler_deadline = now + Duration::from_secs(5);
        let command_deadline = now + Duration::from_secs(20);

        assert_eq!(
            response_wait(handler_deadline, command_deadline, now),
            Some(ResponseWait::Handler(handler_deadline))
        );
        assert_eq!(
            response_wait(handler_deadline, command_deadline, handler_deadline),
            None
        );
        assert_eq!(
            response_wait(command_deadline, command_deadline, now),
            Some(ResponseWait::Command(command_deadline))
        );
    }

    #[test]
    fn services_a_handler_when_its_optional_wait_expires() {
        let now = Instant::now();
        let handler_deadline = now + Duration::from_secs(5);
        let command_deadline = now + Duration::from_secs(20);
        let mut calls = 0;

        let message = wait_for_response_message(
            handler_deadline,
            command_deadline,
            now,
            |wait| {
                assert_eq!(wait, ResponseWait::Handler(handler_deadline));
                Ok(None::<String>)
            },
            || {
                calls += 1;
                Ok(())
            },
        )
        .unwrap();

        assert!(message.is_none());
        assert_eq!(calls, 1);
    }

    #[test]
    fn services_an_expired_handler_deadline_without_reading_the_wire() {
        let now = Instant::now();
        let handler_deadline = now - Duration::from_secs(1);
        let command_deadline = now + Duration::from_secs(20);
        let mut reads = 0;
        let mut calls = 0;

        let message = wait_for_response_message(
            handler_deadline,
            command_deadline,
            now,
            |_| {
                reads += 1;
                Ok(None::<String>)
            },
            || {
                calls += 1;
                Ok(())
            },
        )
        .unwrap();

        assert!(message.is_none());
        assert_eq!(reads, 0);
        assert_eq!(calls, 1);
    }

    #[test]
    fn accepts_only_well_formed_cdp_responses() {
        assert_eq!(
            response_result(json!({ "result": {} }), "Test").unwrap(),
            json!({})
        );
        assert!(response_result(json!({ "error": { "code": -1 } }), "Test").is_err());
        assert!(response_result(json!({}), "Test").is_err());
        assert!(response_result(json!(null), "Test").is_err());
    }
}
