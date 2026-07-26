use std::fmt;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(any(target_os = "macos", test))]
mod macos_logic;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "macos")]
use macos as backend;
#[cfg(target_os = "windows")]
use windows as backend;

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
compile_error!("codex-fast supports only Windows and macOS");

pub(crate) const APP_SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
const PATCH_ABORT_EXIT_CODE: u32 = 0xC0DE;
/// How long either poll loop — process exit or pipe readability — sleeps between checks.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Debug)]
pub(crate) struct IdentityFile {
    pub label: &'static str,
    pub path: PathBuf,
}

#[derive(Debug)]
pub(crate) struct CodexInstall {
    pub identity: String,
    pub install_path: PathBuf,
    pub executable: PathBuf,
    pub app_asar: PathBuf,
    pub identity_files: Vec<IdentityFile>,
    native: backend::NativeInstall,
}

use backend::NativePipe;
pub(crate) use backend::{
    LaunchedApp, acquire_launcher_guard, discover_codex_install, enable_debug_console,
    is_codex_app_running, show_dialog,
};

#[derive(Clone, Copy)]
pub(crate) enum DialogKind {
    Error,
    Info,
    Warning,
}

#[derive(Debug)]
pub(crate) struct AppExited(pub u32);

impl fmt::Display for AppExited {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Codex exited with code {}", self.0)
    }
}

impl std::error::Error for AppExited {}

#[derive(Debug)]
pub(crate) struct AppAlreadyRunning;

impl fmt::Display for AppAlreadyRunning {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Codex App is already running")
    }
}

impl std::error::Error for AppAlreadyRunning {}

pub(crate) struct PipeTransport {
    native: NativePipe,
    pending: Vec<u8>,
    pending_search_start: usize,
}

impl LaunchedApp {
    /// Polls until the app exits or `timeout` elapses. Returns `None` on timeout.
    pub(crate) fn wait_for_exit(&self, timeout: Duration) -> Result<Option<u32>> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(exit_code) = self.exit_code()? {
                return Ok(Some(exit_code));
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let wait = deadline.saturating_duration_since(now).min(POLL_INTERVAL);
            if !wait.is_zero() {
                thread::sleep(wait);
            }
        }
    }
}

pub(crate) fn launch_codex_with_pipe(
    install: &CodexInstall,
    startup_frame: &[u8],
) -> Result<(LaunchedApp, PipeTransport)> {
    let (app, native) = backend::launch_codex_with_pipe(install, startup_frame)?;
    Ok((app, PipeTransport::new(native)))
}

fn is_valid_lock_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Writes every byte of `frame`, mapping both write errors and a zero-byte write
/// through `on_error`. Callers differ only in that recovery: before launch there is
/// no process to interrogate, afterwards a stalled pipe may mean the app exited.
fn write_all(
    pipe: &NativePipe,
    frame: &[u8],
    on_error: impl Fn(anyhow::Error) -> anyhow::Error,
) -> Result<()> {
    let mut offset = 0;
    while offset < frame.len() {
        let written = pipe.write(&frame[offset..]).map_err(&on_error)?;
        if written == 0 {
            return Err(on_error(anyhow!("native pipe wrote zero bytes")));
        }
        offset += written;
    }
    Ok(())
}

/// Arms auto-attach before the app exists, so no target can run before we intercept.
/// There is no process to interrogate yet, so write errors pass through as-is.
fn write_startup_frame(pipe: &NativePipe, frame: &[u8]) -> Result<()> {
    write_all(pipe, frame, |error| {
        error.context("write CDP startup frame before launch")
    })
}

impl PipeTransport {
    fn new(native: NativePipe) -> Self {
        Self {
            native,
            pending: Vec::new(),
            pending_search_start: 0,
        }
    }

    pub(crate) fn send(&self, app: &LaunchedApp, mut payload: String) -> Result<()> {
        payload.push('\0');
        write_all(&self.native, payload.as_bytes(), |error| {
            transport_error(app, error)
        })
    }

    pub(crate) fn next_message(&mut self, app: &LaunchedApp, deadline: Instant) -> Result<String> {
        if let Some(message) = self.next_message_optional(app, deadline)? {
            return Ok(message);
        }
        transport_failure(app, "timed out waiting for CDP message")
    }

    pub(crate) fn next_message_optional(
        &mut self,
        app: &LaunchedApp,
        deadline: Instant,
    ) -> Result<Option<String>> {
        loop {
            if let Some(message) =
                take_pending_message(&mut self.pending, &mut self.pending_search_start)?
            {
                return Ok(Some(message));
            }

            if let Some(exit_code) = app.exit_code()? {
                return Err(AppExited(exit_code).into());
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }

            let wait = deadline.saturating_duration_since(now).min(POLL_INTERVAL);
            if !self
                .native
                .wait_readable(wait)
                .or_else(|error| transport_failure(app, error))?
            {
                continue;
            }

            let mut chunk = [0u8; 65_536];
            let read = self
                .native
                .read(&mut chunk)
                .or_else(|error| transport_failure(app, error))?;
            if read == 0 {
                return transport_failure(app, "native pipe reached EOF");
            }
            self.pending.extend_from_slice(&chunk[..read]);
        }
    }
}

fn take_pending_message(pending: &mut Vec<u8>, search_start: &mut usize) -> Result<Option<String>> {
    let Some(offset) = pending[*search_start..].iter().position(|byte| *byte == 0) else {
        *search_start = pending.len();
        return Ok(None);
    };
    let index = *search_start + offset;
    let mut framed = pending.drain(..=index).collect::<Vec<_>>();
    framed.pop();
    *search_start = 0;
    Ok(Some(String::from_utf8(framed)?))
}

/// A transport fault usually means the app is going away, so give it a moment to exit:
/// a clean exit code is more actionable than the raw I/O error that surfaced first.
fn transport_error(app: &LaunchedApp, message: impl fmt::Display) -> anyhow::Error {
    match app.wait_for_exit(APP_SHUTDOWN_GRACE) {
        Ok(Some(exit_code)) => AppExited(exit_code).into(),
        Ok(None) => anyhow!("{message}"),
        Err(error) => error,
    }
}

fn transport_failure<T>(app: &LaunchedApp, message: impl fmt::Display) -> Result<T> {
    Err(transport_error(app, message))
}

#[cfg(test)]
mod tests {
    use super::take_pending_message;

    #[test]
    fn nul_frames_survive_partial_reads_and_keep_following_data() {
        let mut pending = br#"{"id":1"#.to_vec();
        let mut search_start = 0;
        assert!(
            take_pending_message(&mut pending, &mut search_start)
                .unwrap()
                .is_none()
        );

        pending.extend_from_slice(b"}\0{\"method\":\"ready\"}\0tail");
        assert_eq!(
            take_pending_message(&mut pending, &mut search_start)
                .unwrap()
                .as_deref(),
            Some(r#"{"id":1}"#)
        );
        assert_eq!(
            take_pending_message(&mut pending, &mut search_start)
                .unwrap()
                .as_deref(),
            Some(r#"{"method":"ready"}"#)
        );
        assert_eq!(pending, b"tail");
    }

    #[test]
    fn nul_frame_requires_utf8() {
        let mut pending = vec![0xff, 0];
        let mut search_start = 0;
        assert!(take_pending_message(&mut pending, &mut search_start).is_err());
    }
}
