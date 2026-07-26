#![allow(non_snake_case)]

use std::ffi::c_void;
use std::fs;
use std::mem::{size_of, zeroed};
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::ResolveResult;
use quick_xml::{NsReader, XmlVersion};

use super::{
    AppAlreadyRunning, CodexInstall, IdentityFile, PATCH_ABORT_EXIT_CODE, is_valid_lock_identifier,
};

type Handle = *mut c_void;
type Bool = i32;
type Dword = u32;

const CODEX_PACKAGE_FAMILY: &str = "OpenAI.Codex_2p2nqsd0c76g0";
const TRUE: Bool = 1;
const FALSE: Bool = 0;
const ATTACH_PARENT_PROCESS: Dword = u32::MAX;
const HANDLE_FLAG_INHERIT: Dword = 1;
const PROCESS_QUERY_LIMITED_INFORMATION: Dword = 0x0000_1000;
const CREATE_SUSPENDED: Dword = 0x0000_0004;
const EXTENDED_STARTUPINFO_PRESENT: Dword = 0x0008_0000;
const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;
const ERROR_INSUFFICIENT_BUFFER: i32 = 122;
const ERROR_ALREADY_EXISTS: Dword = 183;
const STILL_ACTIVE: Dword = 259;
const MB_ICONERROR: Dword = 0x0000_0010;
const MB_ICONWARNING: Dword = 0x0000_0030;
const MB_ICONINFORMATION: Dword = 0x0000_0040;
const MB_SETFOREGROUND: Dword = 0x0001_0000;

#[repr(C)]
struct SecurityAttributes {
    nLength: Dword,
    lpSecurityDescriptor: *mut c_void,
    bInheritHandle: Bool,
}

#[repr(C)]
struct StartupInfoW {
    cb: Dword,
    lpReserved: *mut u16,
    lpDesktop: *mut u16,
    lpTitle: *mut u16,
    dwX: Dword,
    dwY: Dword,
    dwXSize: Dword,
    dwYSize: Dword,
    dwXCountChars: Dword,
    dwYCountChars: Dword,
    dwFillAttribute: Dword,
    dwFlags: Dword,
    wShowWindow: u16,
    cbReserved2: u16,
    lpReserved2: *mut u8,
    hStdInput: Handle,
    hStdOutput: Handle,
    hStdError: Handle,
}

#[repr(C)]
struct StartupInfoExW {
    StartupInfo: StartupInfoW,
    lpAttributeList: *mut c_void,
}

#[repr(C)]
struct ProcessInformation {
    hProcess: Handle,
    hThread: Handle,
    dwProcessId: Dword,
    dwThreadId: Dword,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn AllocConsole() -> Bool;
    fn AttachConsole(process_id: Dword) -> Bool;
    fn CloseHandle(handle: Handle) -> Bool;
    fn CreateMutexW(
        attributes: *mut SecurityAttributes,
        initial_owner: Bool,
        name: *const u16,
    ) -> Handle;
    fn OpenProcess(desired_access: Dword, inherit_handle: Bool, process_id: Dword) -> Handle;
    fn K32EnumProcesses(
        process_ids: *mut Dword,
        buffer_size: Dword,
        bytes_returned: *mut Dword,
    ) -> Bool;
    fn CreatePipe(
        read: *mut Handle,
        write: *mut Handle,
        attributes: *mut SecurityAttributes,
        size: Dword,
    ) -> Bool;
    fn SetHandleInformation(handle: Handle, mask: Dword, flags: Dword) -> Bool;
    fn InitializeProcThreadAttributeList(
        list: *mut c_void,
        count: Dword,
        flags: Dword,
        size: *mut usize,
    ) -> Bool;
    fn UpdateProcThreadAttribute(
        list: *mut c_void,
        flags: Dword,
        attribute: usize,
        value: *mut c_void,
        value_size: usize,
        previous: *mut c_void,
        return_size: *mut usize,
    ) -> Bool;
    fn DeleteProcThreadAttributeList(list: *mut c_void);
    fn CreateProcessW(
        application_name: *const u16,
        command_line: *mut u16,
        process_attributes: *mut SecurityAttributes,
        thread_attributes: *mut SecurityAttributes,
        inherit_handles: Bool,
        creation_flags: Dword,
        environment: *mut c_void,
        current_directory: *const u16,
        startup_info: *mut StartupInfoW,
        process_information: *mut ProcessInformation,
    ) -> Bool;
    fn ResumeThread(thread: Handle) -> Dword;
    fn TerminateProcess(process: Handle, exit_code: Dword) -> Bool;
    fn GetExitCodeProcess(process: Handle, exit_code: *mut Dword) -> Bool;
    fn GetConsoleWindow() -> Handle;
    fn GetLastError() -> Dword;
    fn WriteFile(
        file: Handle,
        buffer: *const c_void,
        bytes_to_write: Dword,
        bytes_written: *mut Dword,
        overlapped: *mut c_void,
    ) -> Bool;
    fn ReadFile(
        file: Handle,
        buffer: *mut c_void,
        bytes_to_read: Dword,
        bytes_read: *mut Dword,
        overlapped: *mut c_void,
    ) -> Bool;
    fn PeekNamedPipe(
        pipe: Handle,
        buffer: *mut c_void,
        buffer_size: Dword,
        bytes_read: *mut Dword,
        total_available: *mut Dword,
        bytes_left: *mut Dword,
    ) -> Bool;
    fn GetPackageFullName(process: Handle, length: *mut u32, value: *mut u16) -> i32;
    fn GetPackageFamilyName(process: Handle, length: *mut u32, value: *mut u16) -> i32;
    fn GetApplicationUserModelId(process: Handle, length: *mut u32, value: *mut u16) -> i32;
    fn QueryFullProcessImageNameW(
        process: Handle,
        flags: Dword,
        value: *mut u16,
        length: *mut Dword,
    ) -> Bool;
    fn GetPackagesByPackageFamily(
        package_family_name: *const u16,
        count: *mut u32,
        package_full_names: *mut *mut u16,
        buffer_length: *mut u32,
        buffer: *mut u16,
    ) -> i32;
    fn GetPackagePathByFullName(
        package_full_name: *const u16,
        path_length: *mut u32,
        path: *mut u16,
    ) -> i32;
}

#[link(name = "user32")]
unsafe extern "system" {
    fn MessageBoxW(window: Handle, text: *const u16, caption: *const u16, kind: Dword) -> i32;
}

#[derive(Debug)]
pub(crate) struct NativeInstall {
    package_family_name: String,
    aumid: String,
}

#[derive(Debug)]
struct CodexPackage {
    package_family_name: String,
    package_full_name: String,
    install_path: PathBuf,
}

pub(crate) struct LaunchedApp {
    process: OwnedHandle,
    pid: u32,
}

pub(crate) struct LauncherGuard {
    _handle: OwnedHandle,
}

pub(crate) struct NativePipe {
    read: OwnedHandle,
    write: OwnedHandle,
}

struct OwnedHandle(Handle);

/// A `PROC_THREAD_ATTRIBUTE_LIST` plus the buffer backing it, deleted together on drop.
/// Only constructed once the list is initialized, so dropping it is always correct.
struct AttributeList {
    storage: Vec<usize>,
}

/// A suspended process that is killed on drop unless [`SuspendedProcess::resume`]
/// hands ownership to a [`LaunchedApp`]. Every failure between `CreateProcessW` and
/// `ResumeThread` therefore terminates the child without needing its own cleanup path.
struct SuspendedProcess {
    process: Option<OwnedHandle>,
    thread: OwnedHandle,
    pid: u32,
}

#[derive(Debug)]
struct ManifestApplication {
    app_id: String,
    executable: String,
}

pub(crate) fn discover_codex_install() -> Result<CodexInstall> {
    let package = discover_codex_package(CODEX_PACKAGE_FAMILY)?;
    let manifest = package.install_path.join("AppxManifest.xml");
    let application = parse_appx_application(&manifest)?;
    let executable = package
        .install_path
        .join(application.executable.replace('/', "\\"));
    let app_asar = package
        .install_path
        .join("app")
        .join("resources")
        .join("app.asar");
    let appx_signature = package.install_path.join("AppxSignature.p7x");

    if !executable.is_file() {
        bail!("manifest executable is missing: {}", executable.display());
    }
    if !app_asar.is_file() {
        bail!("app.asar is missing: {}", app_asar.display());
    }
    if !appx_signature.is_file() {
        bail!("AppxSignature.p7x is missing: {}", appx_signature.display());
    }

    let aumid = format!("{}!{}", package.package_family_name, application.app_id);
    let identity = package.package_full_name;
    let install_path = package.install_path;
    let native = NativeInstall {
        package_family_name: package.package_family_name,
        aumid,
    };

    Ok(CodexInstall {
        identity,
        install_path,
        executable,
        app_asar,
        identity_files: vec![
            IdentityFile {
                label: "AppxManifest.xml",
                path: manifest,
            },
            IdentityFile {
                label: "AppxSignature.p7x",
                path: appx_signature,
            },
        ],
        native,
    })
}

pub(crate) fn acquire_launcher_guard(install: &CodexInstall) -> Result<LauncherGuard> {
    let package_family_name = &install.native.package_family_name;
    if !is_valid_lock_identifier(package_family_name) {
        bail!("unsupported package family name {package_family_name:?}");
    }
    let name = wide(&format!("Local\\codex-fast.launch.{package_family_name}"));
    let handle = unsafe { CreateMutexW(null_mut(), FALSE, name.as_ptr()) };
    let status = unsafe { GetLastError() };
    if handle.is_null() {
        bail!("CreateMutexW failed (Win32 error {status})");
    }
    let guard = LauncherGuard {
        _handle: OwnedHandle(handle),
    };
    if status == ERROR_ALREADY_EXISTS {
        return Err(AppAlreadyRunning.into());
    }
    Ok(guard)
}

pub(crate) fn is_codex_app_running(
    install: &CodexInstall,
    excluded_pid: Option<u32>,
) -> Result<bool> {
    is_app_running(
        &install.native.package_family_name,
        &install.native.aumid,
        excluded_pid,
    )
}

pub(super) fn launch_codex_with_pipe(
    install: &CodexInstall,
    startup_frame: &[u8],
) -> Result<(LaunchedApp, NativePipe)> {
    let executable = &install.executable;
    if !executable.is_file() {
        bail!("missing executable: {}", executable.display());
    }

    let (child_read, parent_write) = create_pipe()?;
    let (parent_read, child_write) = create_pipe()?;
    clear_inherit(parent_write.raw())?;
    clear_inherit(parent_read.raw())?;
    let native = NativePipe {
        read: parent_read,
        write: parent_write,
    };
    super::write_startup_frame(&native, startup_frame)?;

    let mut suspended = spawn_suspended(executable, &child_read, &child_write)?;
    drop(child_read);
    drop(child_write);

    // Everything below runs before the child executes a single instruction, and any
    // early return drops `suspended`, which terminates it.
    suspended.verify_identity(install)?;
    if is_app_running(
        &install.native.package_family_name,
        &install.native.aumid,
        Some(suspended.pid),
    )? {
        // Report a failed kill here: a surviving suspended duplicate is worse news
        // than the duplicate we were about to report.
        suspended.terminate()?;
        return Err(AppAlreadyRunning.into());
    }

    let app = suspended.resume()?;
    let resumed_package = app.identity()?;
    let resumed_aumid = query_aumid(app.process.raw())?;
    if resumed_package != install.identity || resumed_aumid != install.native.aumid {
        app.abort_patch();
        bail!(
            "resumed process identity mismatch: package={resumed_package}, aumid={resumed_aumid}"
        );
    }

    Ok((app, native))
}

/// Starts the app suspended with only the two pipe handles inherited, telling Chromium
/// which descriptors carry the CDP conversation.
fn spawn_suspended(
    executable: &Path,
    child_read: &OwnedHandle,
    child_write: &OwnedHandle,
) -> Result<SuspendedProcess> {
    let child_read_value = child_read.raw() as usize;
    let child_write_value = child_write.raw() as usize;
    if child_read_value > u32::MAX as usize || child_write_value > u32::MAX as usize {
        bail!("pipe handle does not fit Chromium uint32 parser");
    }

    // `inherited` must outlive `attributes`: Win32 requires the value passed to
    // UpdateProcThreadAttribute to stay alive until the attribute list is deleted.
    // Declaring it first gives it a later drop, since locals drop in reverse order.
    let mut inherited = [child_read.raw(), child_write.raw()];
    let mut attributes = AttributeList::with_inherited_handles(&mut inherited)?;

    let executable_text = executable.display().to_string();
    let command = format!(
        "\"{executable_text}\" --remote-debugging-pipe --remote-debugging-io-pipes={child_read_value},{child_write_value}"
    );
    let mut command_wide = wide(&command);
    let executable_wide = wide(&executable_text);
    let current_directory = executable
        .parent()
        .ok_or_else(|| anyhow!("invalid executable directory"))?
        .display()
        .to_string();
    let current_directory_wide = wide(&current_directory);

    let mut startup: StartupInfoExW = unsafe { zeroed() };
    startup.StartupInfo.cb = size_of::<StartupInfoExW>() as u32;
    startup.lpAttributeList = attributes.as_ptr();
    let mut info: ProcessInformation = unsafe { zeroed() };
    let created = unsafe {
        CreateProcessW(
            executable_wide.as_ptr(),
            command_wide.as_mut_ptr(),
            null_mut(),
            null_mut(),
            TRUE,
            CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
            null_mut(),
            current_directory_wide.as_ptr(),
            &mut startup.StartupInfo,
            &mut info,
        )
    };
    if created == 0 {
        bail!("{}", last_error("CreateProcessW"));
    }
    SuspendedProcess::new(&info)
}

pub(crate) fn enable_debug_console() -> Result<()> {
    if !unsafe { GetConsoleWindow() }.is_null() {
        return Ok(());
    }
    if unsafe { AttachConsole(ATTACH_PARENT_PROCESS) } != 0 {
        return Ok(());
    }
    if unsafe { AllocConsole() } == 0 {
        bail!("{}", last_error("AllocConsole"));
    }
    Ok(())
}

pub(crate) fn show_dialog(message: &str, kind: super::DialogKind) {
    let icon = match kind {
        super::DialogKind::Error => MB_ICONERROR,
        super::DialogKind::Info => MB_ICONINFORMATION,
        super::DialogKind::Warning => MB_ICONWARNING,
    };
    show_message_box(message, icon);
}

impl LaunchedApp {
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    pub(crate) fn image_path(&self) -> Result<String> {
        let mut buffer = vec![0u16; 32_768];
        let mut length = buffer.len() as u32;
        if unsafe {
            QueryFullProcessImageNameW(self.process.raw(), 0, buffer.as_mut_ptr(), &mut length)
        } == 0
        {
            bail!("{}", last_error("QueryFullProcessImageNameW"));
        }
        Ok(String::from_utf16_lossy(&buffer[..length as usize]))
    }

    pub(crate) fn identity(&self) -> Result<String> {
        query_package_identity(self.process.raw())
    }

    pub(crate) fn exit_code(&self) -> Result<Option<u32>> {
        let mut exit_code = 0;
        if unsafe { GetExitCodeProcess(self.process.raw(), &mut exit_code) } == 0 {
            bail!("{}", last_error("GetExitCodeProcess"));
        }
        if exit_code == STILL_ACTIVE {
            Ok(None)
        } else {
            Ok(Some(exit_code))
        }
    }

    pub(crate) fn abort_patch(&self) {
        unsafe {
            TerminateProcess(self.process.raw(), PATCH_ABORT_EXIT_CODE);
        }
    }
}

impl Drop for LaunchedApp {
    fn drop(&mut self) {
        self.abort_patch();
    }
}

impl NativePipe {
    pub(crate) fn write(&self, buffer: &[u8]) -> Result<usize> {
        let size = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        let mut written = 0;
        if unsafe {
            WriteFile(
                self.write.raw(),
                buffer.as_ptr().cast::<c_void>(),
                size,
                &mut written,
                null_mut(),
            )
        } == 0
        {
            bail!("{}", last_error("WriteFile"));
        }
        Ok(written as usize)
    }

    pub(crate) fn wait_readable(&self, timeout: Duration) -> Result<bool> {
        if self.available()? > 0 {
            return Ok(true);
        }
        if !timeout.is_zero() {
            thread::sleep(timeout);
        }
        Ok(self.available()? > 0)
    }

    pub(crate) fn read(&self, buffer: &mut [u8]) -> Result<usize> {
        let size = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
        let mut read = 0;
        if unsafe {
            ReadFile(
                self.read.raw(),
                buffer.as_mut_ptr().cast::<c_void>(),
                size,
                &mut read,
                null_mut(),
            )
        } == 0
        {
            bail!("{}", last_error("ReadFile"));
        }
        Ok(read as usize)
    }

    fn available(&self) -> Result<u32> {
        let mut available = 0;
        if unsafe {
            PeekNamedPipe(
                self.read.raw(),
                null_mut(),
                0,
                null_mut(),
                &mut available,
                null_mut(),
            )
        } == 0
        {
            bail!("{}", last_error("PeekNamedPipe"));
        }
        Ok(available)
    }
}

impl OwnedHandle {
    fn new(value: Handle) -> Result<Self> {
        if value.is_null() {
            bail!("received a null Win32 handle");
        }
        Ok(Self(value))
    }

    fn raw(&self) -> Handle {
        self.0
    }
}

impl AttributeList {
    /// Builds a one-entry list naming exactly the handles the child may inherit.
    ///
    /// The list stores a pointer to `handles` rather than copying it, so the caller must
    /// keep that array alive until this [`AttributeList`] is dropped.
    fn with_inherited_handles(handles: &mut [Handle; 2]) -> Result<Self> {
        let mut size = 0usize;
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size);
        }
        if size == 0 {
            bail!("{}", last_error("InitializeProcThreadAttributeList(size)"));
        }

        // Initialize the raw buffer first: only once the list exists does it need
        // deleting, so `Self` is constructed exactly when `Drop` becomes correct.
        // Moving the `Vec` afterwards keeps the heap allocation — and this pointer — put.
        let mut storage = vec![0usize; size.div_ceil(size_of::<usize>())];
        if unsafe {
            InitializeProcThreadAttributeList(
                storage.as_mut_ptr().cast::<c_void>(),
                1,
                0,
                &mut size,
            )
        } == 0
        {
            bail!("{}", last_error("InitializeProcThreadAttributeList"));
        }
        let mut list = Self { storage };

        let updated = unsafe {
            UpdateProcThreadAttribute(
                list.as_ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                handles.as_mut_ptr().cast::<c_void>(),
                size_of::<[Handle; 2]>(),
                null_mut(),
                null_mut(),
            )
        };
        if updated == 0 {
            bail!("{}", last_error("UpdateProcThreadAttribute"));
        }
        Ok(list)
    }

    fn as_ptr(&mut self) -> *mut c_void {
        self.storage.as_mut_ptr().cast::<c_void>()
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.as_ptr());
        }
    }
}

impl SuspendedProcess {
    fn new(info: &ProcessInformation) -> Result<Self> {
        Ok(Self {
            process: Some(OwnedHandle::new(info.hProcess)?),
            thread: OwnedHandle::new(info.hThread)?,
            pid: info.dwProcessId,
        })
    }

    fn raw(&self) -> Handle {
        self.process.as_ref().expect("process handle").raw()
    }

    /// Confirms the suspended child is the package we resolved, before it runs any code.
    fn verify_identity(&self, install: &CodexInstall) -> Result<()> {
        let package = query_package_identity(self.raw());
        let aumid = query_aumid(self.raw());
        match (&package, &aumid) {
            (Ok(package), Ok(aumid))
                if package == &install.identity && aumid == &install.native.aumid =>
            {
                Ok(())
            }
            _ => bail!("suspended process identity mismatch: package={package:?}, aumid={aumid:?}"),
        }
    }

    /// Kills the child now instead of at drop, so a failed kill is reported rather than
    /// silently leaking a suspended process. The handle is only released once the kill
    /// succeeds, so a failure still leaves `Drop` able to try again.
    fn terminate(&mut self) -> Result<()> {
        let Some(process) = self.process.as_ref() else {
            return Ok(());
        };
        if unsafe { TerminateProcess(process.raw(), PATCH_ABORT_EXIT_CODE) } == 0 {
            bail!("{}", last_error("TerminateProcess(suspended duplicate)"));
        }
        self.process.take();
        Ok(())
    }

    /// Lets the child run. On success ownership moves to the returned [`LaunchedApp`],
    /// so the abort-on-drop guard no longer applies.
    fn resume(mut self) -> Result<LaunchedApp> {
        if unsafe { ResumeThread(self.thread.raw()) } == u32::MAX {
            bail!("{}", last_error("ResumeThread"));
        }
        Ok(LaunchedApp {
            process: self.process.take().expect("process handle"),
            pid: self.pid,
        })
    }
}

impl Drop for SuspendedProcess {
    fn drop(&mut self) {
        if let Some(process) = &self.process {
            unsafe {
                TerminateProcess(process.raw(), PATCH_ABORT_EXIT_CODE);
            }
        }
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

fn show_message_box(message: &str, icon: Dword) {
    let message = wide(message);
    let title = wide("Codex Fast");
    unsafe {
        MessageBoxW(
            null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            icon | MB_SETFOREGROUND,
        );
    }
}

fn discover_codex_package(package_family_name: &str) -> Result<CodexPackage> {
    let mut full_names = package_full_names_by_family(package_family_name)?;
    full_names.sort_by(|left, right| compare_package_version(left, right).then(left.cmp(right)));
    let package_full_name = full_names
        .pop()
        .ok_or_else(|| anyhow!("no installed package for {package_family_name}"))?;
    let install_path = package_path_by_full_name(&package_full_name)?;
    Ok(CodexPackage {
        package_family_name: package_family_name.to_owned(),
        package_full_name,
        install_path,
    })
}

fn is_app_running(
    expected_family: &str,
    expected_aumid: &str,
    excluded_pid: Option<u32>,
) -> Result<bool> {
    for process_id in process_ids()? {
        if process_id == 0 || Some(process_id) == excluded_pid {
            continue;
        }

        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_id) };
        if handle.is_null() {
            continue;
        }
        let process = OwnedHandle(handle);
        if !query_aumid(process.raw())
            .as_deref()
            .is_ok_and(|aumid| aumid == expected_aumid)
        {
            continue;
        }
        if query_package_family(process.raw())
            .as_deref()
            .is_ok_and(|family| family == expected_family)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn package_full_names_by_family(package_family_name: &str) -> Result<Vec<String>> {
    let family_wide = wide(package_family_name);
    let mut count = 0u32;
    let mut buffer_length = 0u32;
    let first = unsafe {
        GetPackagesByPackageFamily(
            family_wide.as_ptr(),
            &mut count,
            null_mut(),
            &mut buffer_length,
            null_mut(),
        )
    };
    if first != 0 && first != ERROR_INSUFFICIENT_BUFFER {
        bail!("GetPackagesByPackageFamily failed with AppModel error {first}");
    }
    if count == 0 {
        return Ok(Vec::new());
    }

    let mut name_ptrs = vec![null_mut::<u16>(); count as usize];
    let mut buffer = vec![0u16; buffer_length as usize];
    let rc = unsafe {
        GetPackagesByPackageFamily(
            family_wide.as_ptr(),
            &mut count,
            name_ptrs.as_mut_ptr(),
            &mut buffer_length,
            buffer.as_mut_ptr(),
        )
    };
    if rc != 0 {
        bail!("GetPackagesByPackageFamily failed with AppModel error {rc}");
    }

    Ok(name_ptrs
        .into_iter()
        .take(count as usize)
        .filter(|ptr| !ptr.is_null())
        .map(wide_ptr_to_string)
        .collect())
}

fn package_path_by_full_name(package_full_name: &str) -> Result<PathBuf> {
    let name_wide = wide(package_full_name);
    let mut length = 0u32;
    let first = unsafe { GetPackagePathByFullName(name_wide.as_ptr(), &mut length, null_mut()) };
    if first != 0 && first != ERROR_INSUFFICIENT_BUFFER {
        bail!("GetPackagePathByFullName failed with AppModel error {first}");
    }
    if length == 0 {
        bail!("GetPackagePathByFullName returned zero length");
    }

    let mut buffer = vec![0u16; length as usize];
    let rc =
        unsafe { GetPackagePathByFullName(name_wide.as_ptr(), &mut length, buffer.as_mut_ptr()) };
    if rc != 0 {
        bail!("GetPackagePathByFullName failed with AppModel error {rc}");
    }
    Ok(PathBuf::from(trimmed_wide_to_string(&buffer)))
}

fn compare_package_version(left: &str, right: &str) -> std::cmp::Ordering {
    parse_package_version(left).cmp(&parse_package_version(right))
}

fn parse_package_version(value: &str) -> Vec<u64> {
    value
        .split('_')
        .nth(1)
        .unwrap_or_default()
        .split('.')
        .map(|part| part.parse::<u64>().unwrap_or(0))
        .collect()
}

fn create_pipe() -> Result<(OwnedHandle, OwnedHandle)> {
    let mut read = null_mut();
    let mut write = null_mut();
    let mut attributes = SecurityAttributes {
        nLength: size_of::<SecurityAttributes>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: TRUE,
    };
    if unsafe { CreatePipe(&mut read, &mut write, &mut attributes, 0) } == 0 {
        bail!("{}", last_error("CreatePipe"));
    }
    Ok((OwnedHandle::new(read)?, OwnedHandle::new(write)?))
}

fn clear_inherit(handle: Handle) -> Result<()> {
    if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
        bail!("{}", last_error("SetHandleInformation"));
    }
    Ok(())
}

fn query_package_identity(process: Handle) -> Result<String> {
    query_identity(process, GetPackageFullName, "GetPackageFullName")
}

fn query_package_family(process: Handle) -> Result<String> {
    query_identity(process, GetPackageFamilyName, "GetPackageFamilyName")
}

fn query_aumid(process: Handle) -> Result<String> {
    query_identity(
        process,
        GetApplicationUserModelId,
        "GetApplicationUserModelId",
    )
}

fn query_identity(
    process: Handle,
    query: unsafe extern "system" fn(Handle, *mut u32, *mut u16) -> i32,
    label: &str,
) -> Result<String> {
    let mut length = 0;
    let first = unsafe { query(process, &mut length, null_mut()) };
    if first != ERROR_INSUFFICIENT_BUFFER || length == 0 {
        bail!("{label} initial query failed with code {first}");
    }
    let mut buffer = vec![0u16; length as usize];
    let rc = unsafe { query(process, &mut length, buffer.as_mut_ptr()) };
    if rc != 0 {
        bail!("{label} failed with code {rc}");
    }
    Ok(trimmed_wide_to_string(&buffer))
}

fn process_ids() -> Result<Vec<u32>> {
    let mut process_ids = vec![0u32; 1024];
    loop {
        let buffer_size = process_ids
            .len()
            .checked_mul(size_of::<u32>())
            .and_then(|size| u32::try_from(size).ok())
            .ok_or_else(|| anyhow!("process list is too large"))?;
        let mut bytes_returned = 0u32;
        if unsafe { K32EnumProcesses(process_ids.as_mut_ptr(), buffer_size, &mut bytes_returned) }
            == 0
        {
            bail!("{}", last_error("K32EnumProcesses"));
        }
        if bytes_returned < buffer_size {
            process_ids.truncate(bytes_returned as usize / size_of::<u32>());
            return Ok(process_ids);
        }
        process_ids.resize(
            process_ids
                .len()
                .checked_mul(2)
                .ok_or_else(|| anyhow!("process list is too large"))?,
            0,
        );
    }
}

fn parse_appx_application(manifest: &Path) -> Result<ManifestApplication> {
    let xml = fs::read_to_string(manifest)
        .with_context(|| format!("read manifest {}", manifest.display()))?;
    parse_appx_application_xml(&xml)
}

fn parse_appx_application_xml(xml: &str) -> Result<ManifestApplication> {
    let mut reader = NsReader::from_str(xml);
    let mut package_namespace = None;
    let mut candidate = None;

    loop {
        let (namespace, event) = reader
            .read_resolved_event()
            .context("parse AppxManifest.xml")?;
        let namespace = match namespace {
            ResolveResult::Unbound => None,
            ResolveResult::Bound(namespace) => Some(namespace.into_inner()),
            ResolveResult::Unknown(prefix) => {
                bail!(
                    "AppxManifest.xml uses undeclared namespace prefix {}",
                    String::from_utf8_lossy(&prefix)
                )
            }
        };

        match event {
            Event::Start(element) | Event::Empty(element) => {
                if package_namespace.is_none() {
                    if element.local_name().as_ref() != b"Package" {
                        bail!("AppxManifest.xml root element is not Package");
                    }
                    package_namespace = Some(namespace.map(<[u8]>::to_vec));
                }

                if candidate.is_none()
                    && element.local_name().as_ref() == b"Application"
                    && package_namespace
                        .as_ref()
                        .is_some_and(|expected| expected.as_deref() == namespace)
                    && let Some(application) = application_attributes(&element)?
                    && is_chatgpt_executable(&application.executable)
                {
                    candidate = Some(application);
                }
            }
            Event::DocType(_) => bail!("AppxManifest.xml must not contain a document type"),
            Event::Eof => break,
            _ => {}
        }
    }

    candidate.ok_or_else(|| anyhow!("AppxManifest.xml does not define a ChatGPT.exe application"))
}

fn is_chatgpt_executable(executable: &str) -> bool {
    executable
        .rsplit(['/', '\\'])
        .next()
        .is_some_and(|name| name.eq_ignore_ascii_case("ChatGPT.exe"))
}

fn application_attributes(element: &BytesStart<'_>) -> Result<Option<ManifestApplication>> {
    let mut app_id = None;
    let mut executable = None;
    for attribute in element.attributes() {
        let attribute = attribute.context("parse Application attribute")?;
        let target = match attribute.key.as_ref() {
            b"Id" => &mut app_id,
            b"Executable" => &mut executable,
            _ => continue,
        };
        if target.is_some() {
            bail!(
                "duplicate Application attribute {}",
                String::from_utf8_lossy(attribute.key.as_ref())
            );
        }
        *target = Some(
            attribute
                .decoded_and_normalized_value(XmlVersion::Implicit1_0, element.decoder())
                .context("decode Application attribute")?
                .into_owned(),
        );
    }

    Ok(app_id
        .zip(executable)
        .map(|(app_id, executable)| ManifestApplication { app_id, executable }))
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn wide_ptr_to_string(ptr: *mut u16) -> String {
    let mut len = 0usize;
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    }
}

fn trimmed_wide_to_string(buffer: &[u16]) -> String {
    let used = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..used])
}

fn last_error(operation: &str) -> String {
    format!("{operation} failed with Win32 error {}", unsafe {
        GetLastError()
    })
}

#[cfg(test)]
mod tests {
    use super::{acquire_launcher_guard, parse_appx_application_xml};
    use crate::platform::{AppAlreadyRunning, CodexInstall, IdentityFile};
    use std::path::PathBuf;

    fn test_install(family: String) -> CodexInstall {
        CodexInstall {
            identity: family.clone(),
            install_path: PathBuf::new(),
            executable: PathBuf::new(),
            app_asar: PathBuf::new(),
            identity_files: Vec::<IdentityFile>::new(),
            native: super::NativeInstall {
                package_family_name: family.clone(),
                aumid: family,
            },
        }
    }

    #[test]
    fn launcher_guard_is_exclusive_and_released_on_drop() {
        let family = format!("test.{}.launcher_guard", std::process::id());
        let install = test_install(family);
        let first = acquire_launcher_guard(&install).unwrap();
        let second = acquire_launcher_guard(&install).err().unwrap();
        assert!(second.downcast_ref::<AppAlreadyRunning>().is_some());

        drop(first);
        acquire_launcher_guard(&install).unwrap();
    }

    #[test]
    fn resolves_namespaces_and_attribute_entities() {
        let application = parse_appx_application_xml(
            r#"<p:Package xmlns:p="urn:package" xmlns:a="urn:package">
                <a:Applications>
                  <a:Application Id="A&amp;B" Executable="app&#x2f;ChatGPT.exe" />
                </a:Applications>
              </p:Package>"#,
        )
        .unwrap();

        assert_eq!(application.app_id, "A&B");
        assert_eq!(application.executable, "app/ChatGPT.exe");
    }

    #[test]
    fn matches_the_executable_name_not_a_suffix() {
        let application = parse_appx_application_xml(
            r#"<Package><Applications>
                  <Application Id="Wrong" Executable="NotChatGPT.exe" />
                  <Application Id="Right" Executable="app\ChatGPT.exe" />
                </Applications></Package>"#,
        )
        .unwrap();

        assert_eq!(application.app_id, "Right");
    }

    #[test]
    fn rejects_document_types() {
        let error = parse_appx_application_xml(
            r#"<!DOCTYPE Package><Package><Application Id="App" Executable="ChatGPT.exe" /></Package>"#,
        )
        .unwrap_err();

        assert!(error.to_string().contains("document type"));
    }
}
