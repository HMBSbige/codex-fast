use std::env;
use std::ffi::{c_int, c_short, c_void};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};

use super::macos_logic::{
    COMMAND_FD, RESPONSE_FD, TEMPORARY_FD_MIN, bundle_executable, bundle_paths,
    parse_plistbuddy_output, ps_has_executable,
};
use super::{
    AppAlreadyRunning, CodexInstall, IdentityFile, PATCH_ABORT_EXIT_CODE, is_valid_lock_identifier,
};

#[cfg(not(target_arch = "aarch64"))]
compile_error!("the macOS build supports Apple Silicon only");

const PLIST_BUDDY: &str = "/usr/libexec/PlistBuddy";
const PS: &str = "/bin/ps";
const OSASCRIPT: &str = "/usr/bin/osascript";
const TERMINATE_GRACE: Duration = Duration::from_secs(1);

const F_DUPFD: c_int = 0;
const F_GETFD: c_int = 1;
const F_SETFD: c_int = 2;
const FD_CLOEXEC: c_int = 1;
const LOCK_EX: c_int = 2;
const LOCK_NB: c_int = 4;
const POLLIN: c_short = 0x0001;
const POLLERR: c_short = 0x0008;
const POLLHUP: c_short = 0x0010;
const POLLNVAL: c_short = 0x0020;
const SIGKILL: c_int = 9;
const SIGTERM: c_int = 15;
const ESRCH: c_int = 3;

#[repr(C)]
struct PollFd {
    fd: c_int,
    events: c_short,
    revents: c_short,
}

unsafe extern "C" {
    fn pipe(files: *mut c_int) -> c_int;
    fn fcntl(file: c_int, command: c_int, ...) -> c_int;
    fn dup2(source: c_int, target: c_int) -> c_int;
    fn close(file: c_int) -> c_int;
    fn flock(file: c_int, operation: c_int) -> c_int;
    fn poll(files: *mut PollFd, count: u32, timeout_ms: c_int) -> c_int;
    fn read(file: c_int, buffer: *mut c_void, size: usize) -> isize;
    fn write(file: c_int, buffer: *const c_void, size: usize) -> isize;
    fn setpgid(pid: c_int, process_group: c_int) -> c_int;
    fn kill(pid: c_int, signal: c_int) -> c_int;
}

#[derive(Debug)]
pub(super) struct NativeInstall {
    bundle_identifier: String,
}

pub(crate) struct LaunchedApp {
    child: Mutex<Child>,
    pid: u32,
    image: String,
    identity: String,
}

pub(crate) struct LauncherGuard {
    _file: File,
}

pub(crate) struct NativePipe {
    read: OwnedFd,
    write: OwnedFd,
}

pub(crate) fn discover_codex_install() -> Result<CodexInstall> {
    if let Some(bundle) = env::var_os("CODEX_FAST_APP_BUNDLE") {
        return discover_bundle(PathBuf::from(bundle));
    }

    for candidate in [
        Path::new("/Applications/Codex.app"),
        Path::new("/Applications/ChatGPT.app"),
    ] {
        if candidate.is_dir() {
            return discover_bundle(candidate.to_owned());
        }
    }
    bail!("Codex.app or ChatGPT.app was not found in /Applications")
}

fn discover_bundle(bundle: PathBuf) -> Result<CodexInstall> {
    if !bundle.is_dir() {
        bail!("app bundle is missing: {}", bundle.display());
    }
    let bundle = bundle
        .canonicalize()
        .with_context(|| format!("resolve app bundle {}", bundle.display()))?;
    let paths = bundle_paths(&bundle);
    if !paths.info_plist.is_file() {
        bail!("Info.plist is missing: {}", paths.info_plist.display());
    }

    let plist = read_bundle_info(&paths.info_plist)?;
    let executable = bundle_executable(&bundle, &plist.executable)
        .ok_or_else(|| anyhow!("unsupported CFBundleExecutable {:?}", plist.executable))?;
    if !executable.is_file() {
        bail!("bundle executable is missing: {}", executable.display());
    }
    if !paths.app_asar.is_file() {
        bail!("app.asar is missing: {}", paths.app_asar.display());
    }

    let identity = format!("{} {} ({})", plist.identifier, plist.version, plist.build);
    let mut identity_files = vec![IdentityFile {
        label: "Info.plist",
        path: paths.info_plist,
    }];
    if paths.code_resources.is_file() {
        identity_files.push(IdentityFile {
            label: "CodeResources",
            path: paths.code_resources,
        });
    }

    Ok(CodexInstall {
        identity,
        install_path: bundle,
        executable,
        app_asar: paths.app_asar,
        identity_files,
        native: NativeInstall {
            bundle_identifier: plist.identifier,
        },
    })
}

fn read_bundle_info(info_plist: &Path) -> Result<super::macos_logic::PlistInfo> {
    let output = Command::new(PLIST_BUDDY)
        .args([
            "-c",
            "Print :CFBundleIdentifier",
            "-c",
            "Print :CFBundleExecutable",
            "-c",
            "Print :CFBundleShortVersionString",
            "-c",
            "Print :CFBundleVersion",
        ])
        .arg(info_plist)
        .output()
        .with_context(|| format!("run {PLIST_BUDDY}"))?;
    if !output.status.success() {
        bail!(
            "PlistBuddy failed for {}: {}",
            info_plist.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let stdout = String::from_utf8(output.stdout).context("PlistBuddy output is not UTF-8")?;
    parse_plistbuddy_output(&stdout).map_err(anyhow::Error::msg)
}

pub(crate) fn acquire_launcher_guard(install: &CodexInstall) -> Result<LauncherGuard> {
    let identifier = &install.native.bundle_identifier;
    if !is_valid_lock_identifier(identifier) {
        bail!("unsupported bundle identifier {identifier:?}");
    }
    let lock_path = env::temp_dir().join(format!("codex-fast.launch.{identifier}.lock"));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("open launcher lock {}", lock_path.display()))?;
    if unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            return Err(AppAlreadyRunning.into());
        }
        return Err(error).with_context(|| format!("lock launcher file {}", lock_path.display()));
    }
    Ok(LauncherGuard { _file: file })
}

pub(crate) fn is_codex_app_running(
    install: &CodexInstall,
    excluded_pid: Option<u32>,
) -> Result<bool> {
    let output = Command::new(PS)
        .args(["-axww", "-o", "pid=,command="])
        .output()
        .with_context(|| format!("run {PS}"))?;
    if !output.status.success() {
        bail!(
            "ps failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let stdout = String::from_utf8(output.stdout).context("ps output is not UTF-8")?;
    Ok(ps_has_executable(
        &stdout,
        &install.executable,
        excluded_pid,
    ))
}

pub(super) fn launch_codex_with_pipe(
    install: &CodexInstall,
    startup_frame: &[u8],
) -> Result<(LaunchedApp, NativePipe)> {
    if !install.executable.is_file() {
        bail!("missing executable: {}", install.executable.display());
    }
    if is_codex_app_running(install, None)? {
        return Err(AppAlreadyRunning.into());
    }

    let (child_read, parent_write) = create_pipe()?;
    let (parent_read, child_write) = create_pipe()?;
    let command_source = child_read.as_raw_fd();
    let response_source = child_write.as_raw_fd();
    let inherited = [
        child_read.as_raw_fd(),
        parent_write.as_raw_fd(),
        parent_read.as_raw_fd(),
        child_write.as_raw_fd(),
    ];
    let native = NativePipe {
        read: parent_read,
        write: parent_write,
    };
    super::write_startup_frame(&native, startup_frame)?;

    let executable_text = install.executable.to_string_lossy().into_owned();
    let current_directory = install
        .executable
        .parent()
        .ok_or_else(|| anyhow!("invalid executable directory"))?;
    let mut command = Command::new(&install.executable);
    command
        .arg("--remote-debugging-pipe")
        .current_dir(current_directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(move || prepare_child(command_source, response_source, inherited));
    }
    let child = command
        .spawn()
        .with_context(|| format!("launch {}", install.executable.display()))?;
    let pid = child.id();
    drop(child_read);
    drop(child_write);

    let app = LaunchedApp {
        child: Mutex::new(child),
        pid,
        image: executable_text,
        identity: install.identity.clone(),
    };
    if is_codex_app_running(install, Some(pid))? {
        app.abort_patch();
        return Err(AppAlreadyRunning.into());
    }

    Ok((app, native))
}

/// Moves the two pipe ends onto the descriptors Chromium expects. Both sources come from
/// distinct `create_pipe` calls, so they are always valid and never collide.
fn prepare_child(
    command_source: RawFd,
    response_source: RawFd,
    inherited: [RawFd; 4],
) -> io::Result<()> {
    if unsafe { setpgid(0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let command_copy = unsafe { fcntl(command_source, F_DUPFD, TEMPORARY_FD_MIN) };
    if command_copy < 0 {
        return Err(io::Error::last_os_error());
    }
    let response_copy = unsafe { fcntl(response_source, F_DUPFD, TEMPORARY_FD_MIN) };
    if response_copy < 0 {
        unsafe {
            close(command_copy);
        }
        return Err(io::Error::last_os_error());
    }

    let command_result = unsafe { dup2(command_copy, COMMAND_FD) };
    let command_error = io::Error::last_os_error();
    let response_result = unsafe { dup2(response_copy, RESPONSE_FD) };
    let response_error = io::Error::last_os_error();
    unsafe {
        close(command_copy);
        close(response_copy);
    }
    if command_result < 0 {
        return Err(command_error);
    }
    if response_result < 0 {
        return Err(response_error);
    }

    for file in inherited {
        if file != COMMAND_FD && file != RESPONSE_FD {
            unsafe {
                close(file);
            }
        }
    }
    Ok(())
}

pub(crate) fn enable_debug_console() -> Result<()> {
    Ok(())
}

pub(crate) fn show_dialog(message: &str, kind: super::DialogKind) {
    let icon = match kind {
        super::DialogKind::Error => "stop",
        super::DialogKind::Info => "note",
        super::DialogKind::Warning => "caution",
    };
    let script = format!(
        "display dialog (item 1 of argv) with title \"Codex Fast\" buttons {{\"OK\"}} default button 1 with icon {icon}"
    );
    let _ = Command::new(OSASCRIPT)
        .args([
            "-e",
            "on run argv",
            "-e",
            script.as_str(),
            "-e",
            "end run",
            "--",
        ])
        .arg(message)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

impl LaunchedApp {
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    pub(crate) fn image_path(&self) -> Result<String> {
        Ok(self.image.clone())
    }

    pub(crate) fn identity(&self) -> Result<String> {
        Ok(self.identity.clone())
    }

    pub(crate) fn exit_code(&self) -> Result<Option<u32>> {
        let mut child = self
            .child
            .lock()
            .map_err(|_| anyhow!("Codex child process lock is poisoned"))?;
        Ok(child.try_wait()?.map(exit_code))
    }

    pub(crate) fn abort_patch(&self) {
        if self.exit_code().ok().flatten().is_some() {
            return;
        }
        let _ = signal_process_group(self.pid, SIGTERM);
        if self.wait_for_exit(TERMINATE_GRACE).ok().flatten().is_some() {
            return;
        }
        let _ = signal_process_group(self.pid, SIGKILL);
        let _ = self.wait_for_exit(TERMINATE_GRACE);
    }
}

impl Drop for LaunchedApp {
    fn drop(&mut self) {
        self.abort_patch();
    }
}

impl NativePipe {
    pub(crate) fn write(&self, buffer: &[u8]) -> Result<usize> {
        loop {
            let written = unsafe {
                write(
                    self.write.as_raw_fd(),
                    buffer.as_ptr().cast::<c_void>(),
                    buffer.len(),
                )
            };
            if written >= 0 {
                return Ok(written as usize);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error).context("write CDP pipe");
            }
        }
    }

    pub(crate) fn wait_readable(&self, timeout: Duration) -> Result<bool> {
        let mut descriptor = PollFd {
            fd: self.read.as_raw_fd(),
            events: POLLIN,
            revents: 0,
        };
        let timeout_ms = duration_to_poll_timeout(timeout);
        loop {
            let result = unsafe { poll(&mut descriptor, 1, timeout_ms) };
            if result > 0 {
                if descriptor.revents & POLLNVAL != 0 {
                    bail!("CDP pipe poll reported an invalid file descriptor");
                }
                return Ok(descriptor.revents & (POLLIN | POLLERR | POLLHUP) != 0);
            }
            if result == 0 {
                return Ok(false);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error).context("poll CDP pipe");
            }
        }
    }

    pub(crate) fn read(&self, buffer: &mut [u8]) -> Result<usize> {
        loop {
            let read_count = unsafe {
                read(
                    self.read.as_raw_fd(),
                    buffer.as_mut_ptr().cast::<c_void>(),
                    buffer.len(),
                )
            };
            if read_count >= 0 {
                return Ok(read_count as usize);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error).context("read CDP pipe");
            }
        }
    }
}

fn create_pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut files = [-1; 2];
    loop {
        if unsafe { pipe(files.as_mut_ptr()) } == 0 {
            break;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error).context("create anonymous pipe");
        }
    }
    let read = unsafe { OwnedFd::from_raw_fd(files[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(files[1]) };
    set_close_on_exec(read.as_raw_fd())?;
    set_close_on_exec(write.as_raw_fd())?;
    Ok((read, write))
}

fn set_close_on_exec(file: RawFd) -> Result<()> {
    let flags = unsafe { fcntl(file, F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error()).context("read file descriptor flags");
    }
    if unsafe { fcntl(file, F_SETFD, flags | FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error()).context("set close-on-exec");
    }
    Ok(())
}

fn duration_to_poll_timeout(timeout: Duration) -> c_int {
    if timeout.is_zero() {
        return 0;
    }
    timeout.as_millis().max(1).min(c_int::MAX as u128) as c_int
}

fn exit_code(status: ExitStatus) -> u32 {
    status
        .code()
        .and_then(|code| u32::try_from(code).ok())
        .or_else(|| status.signal().map(|signal| 128 + signal as u32))
        .unwrap_or(PATCH_ABORT_EXIT_CODE)
}

fn signal_process_group(pid: u32, signal: c_int) -> Result<()> {
    let pid = c_int::try_from(pid).context("Codex process id does not fit pid_t")?;
    if unsafe { kill(-pid, signal) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(ESRCH) {
        return Ok(());
    }
    Err(error).context("signal Codex process group")
}
