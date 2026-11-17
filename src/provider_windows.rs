//! Local Windows process creation and lifetime boundary for optional providers.
//!
//! This module owns all native process/job/pipe handles. It is not a sandbox;
//! the Job Object is used to stop an associated one-shot provider tree and
//! release inherited stdio handles.

#![cfg(windows)]

use std::{
    ffi::{OsStr, c_void},
    fs::File,
    io,
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, RawHandle},
    },
    path::Path,
    ptr::{null, null_mut},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, GetLastError, HANDLE, HANDLE_FLAG_INHERIT,
        SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::SECURITY_ATTRIBUTES,
    System::{
        IO::CancelSynchronousIo,
        JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
            QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
        },
        Pipes::CreatePipe,
        Threading::{
            CREATE_NO_WINDOW, EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess,
            InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
            STARTUPINFOEXW, UpdateProcThreadAttribute, WaitForSingleObject,
        },
    },
};

const PROVIDER_EXIT_CODE: u32 = 0xE000_0001;
const ATTRIBUTE_COUNT: u32 = 2;
const MAX_RETAINED_SETUP_HANDLES: usize = 8;
const JOB_POLL_INTERVAL: Duration = Duration::from_millis(10);

pub(super) struct SpawnedProvider {
    pub stdin: File,
    pub stdout: File,
    pub stderr: File,
}

/// A uniquely owned process and non-inheritable job handle. The provider is
/// assigned through PROC_THREAD_ATTRIBUTE_JOB_LIST before its initial thread
/// can run, so there is no post-spawn assignment window.
pub(super) struct NativeChild {
    process: Option<OwnedHandle>,
    job: Option<OwnedHandle>,
    process_exit_observed: bool,
    process_exit_code: Option<u32>,
    active_processes_zero_observed: bool,
    cleanup_faulted: bool,
    retained_setup_handles: Vec<OwnedHandle>,
}

// SAFETY: kernel handles are process-wide values, and this owner only calls
// handle APIs that Windows permits from any thread. It never transfers the
// handle to another process after creation.
unsafe impl Send for NativeChild {}

impl NativeChild {
    pub(super) fn try_wait(&mut self) -> io::Result<Option<u32>> {
        let Some(process_handle) = self.process.as_ref().map(OwnedHandle::raw) else {
            return match (self.process_exit_observed, self.process_exit_code) {
                (true, Some(exit_code)) => Ok(Some(exit_code)),
                _ => Err(io::Error::other(
                    "provider process handle is absent before a complete exit status was recorded",
                )),
            };
        };
        // SAFETY: `process_handle` is owned by this child from CreateProcessW.
        let wait = unsafe { WaitForSingleObject(process_handle, 0) };
        if wait == WAIT_TIMEOUT {
            return Ok(None);
        }
        if !process_wait_confirms_exit(wait) {
            self.cleanup_faulted = true;
            return Err(io::Error::last_os_error());
        }

        let mut exit_code = 0u32;
        // SAFETY: the process handle is valid and `exit_code` is writable.
        if unsafe { GetExitCodeProcess(process_handle, &mut exit_code) } == 0 {
            self.cleanup_faulted = true;
            return Err(io::Error::last_os_error());
        }
        self.process_exit_observed = true;
        self.process_exit_code = Some(exit_code);
        self.close_process()?;
        Ok(Some(exit_code))
    }

    pub(super) fn close_job(&mut self) -> io::Result<()> {
        if !self.process_exit_observed
            || self.process.is_some()
            || !self.active_processes_zero_observed
            || !self.retained_setup_handles.is_empty()
        {
            return Err(io::Error::other(concat!(
                "refusing to release provider Job Object before parent exit, zero active ",
                "processes, and setup-handle release are observed"
            )));
        }
        let Some(job) = self.job.as_mut() else {
            return Ok(());
        };
        if let Err(error) = job.close_checked() {
            self.cleanup_faulted = true;
            return Err(error);
        }
        self.job = None;
        Ok(())
    }

    pub(super) fn close_process(&mut self) -> io::Result<()> {
        if !self.process_exit_observed {
            return Err(io::Error::other(
                "refusing to release provider process handle before exit is observed",
            ));
        }
        let Some(process) = self.process.as_mut() else {
            return Ok(());
        };
        if let Err(error) = process.close_checked() {
            self.cleanup_faulted = true;
            return Err(error);
        }
        self.process = None;
        Ok(())
    }

    pub(super) fn is_closed(&self) -> bool {
        cleanup_complete(
            self.process_exit_observed,
            self.process.is_some(),
            self.job.is_some(),
            self.active_processes_zero_observed,
        ) && self.retained_setup_handles.is_empty()
            && !self.cleanup_faulted
    }

    /// Observe the parent exit, then repeatedly terminate/query the job until
    /// Windows reports no active processes. The Job Object remains owned for
    /// reader joining and is only closed by `close_job` after that boundary.
    pub(super) fn wait_for_job_tree_until(
        &mut self,
        deadline: Instant,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> io::Result<()> {
        loop {
            if cancelled.load(std::sync::atomic::Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "provider cleanup cancelled",
                ));
            }
            if self.observe_job_active_processes_once()? {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.cleanup_faulted = true;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    concat!(
                        "provider Job Object did not reach ActiveProcesses == 0 before the ",
                        "shutdown deadline"
                    ),
                ));
            }
            std::thread::sleep(JOB_POLL_INTERVAL.min(remaining));
        }
    }

    /// One bounded poll. For every positive active count, reissue termination
    /// before the next query to cover descendants created concurrently inside
    /// the job. A zero count is recorded but does not release the job handle.
    fn observe_job_active_processes_once(&mut self) -> io::Result<bool> {
        if !self.process_exit_observed || self.process.is_some() {
            self.cleanup_faulted = true;
            return Err(io::Error::other(concat!(
                "cannot query provider tree completion before observing and releasing ",
                "the parent process handle"
            )));
        }
        self.close_retained_setup_handles()?;
        if self.active_processes_zero_observed {
            return Ok(true);
        }
        let Some(job) = self.job.as_ref().map(OwnedHandle::raw) else {
            self.cleanup_faulted = true;
            return Err(io::Error::other(concat!(
                "provider Job Object handle was released before active-process ",
                "completion was observed"
            )));
        };

        let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
        let mut returned = 0u32;
        // SAFETY: `job` is the uniquely owned query-capable Job Object and the
        // output buffer is correctly sized/aligned for the requested class.
        if unsafe {
            QueryInformationJobObject(
                job,
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                &mut returned,
            )
        } == 0
        {
            self.cleanup_faulted = true;
            return Err(io::Error::last_os_error());
        }
        if returned < size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32 {
            self.cleanup_faulted = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "QueryInformationJobObject returned a short accounting record",
            ));
        }
        if accounting.ActiveProcesses == 0 {
            self.active_processes_zero_observed = true;
            return Ok(true);
        }

        // SAFETY: the Job Object remains owned and the positive accounting
        // count proves at least one associated process is still active.
        if unsafe { TerminateJobObject(job, PROVIDER_EXIT_CODE) } == 0 {
            self.cleanup_faulted = true;
            return Err(io::Error::last_os_error());
        }
        Ok(false)
    }

    fn close_retained_setup_handles(&mut self) -> io::Result<()> {
        let mut index = 0;
        while index < self.retained_setup_handles.len() {
            if let Err(error) = self.retained_setup_handles[index].close_checked() {
                self.cleanup_faulted = true;
                return Err(error);
            }
            self.retained_setup_handles.swap_remove(index);
        }
        Ok(())
    }

    /// Bounded best-effort teardown for failure/cancellation. The job and
    /// helpers remain owned until the parent exit and ActiveProcesses == 0
    /// have both been observed; any error or deadline leaves the session for
    /// the bounded quarantine reaper.
    pub(super) fn terminate_and_reap(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if !self.process_exit_observed {
                let Some(process_handle) = self.process.as_ref().map(OwnedHandle::raw) else {
                    self.cleanup_faulted = true;
                    return false;
                };
                let remaining = deadline.saturating_duration_since(Instant::now());
                // SAFETY: process handle is uniquely owned and the wait is
                // bounded by the caller's cleanup deadline.
                let wait = unsafe {
                    WaitForSingleObject(
                        process_handle,
                        duration_to_millis(remaining.min(JOB_POLL_INTERVAL)),
                    )
                };
                if process_wait_confirms_exit(wait) {
                    let mut exit_code = 0u32;
                    // SAFETY: the signaled process handle is valid and writable.
                    if unsafe { GetExitCodeProcess(process_handle, &mut exit_code) } == 0 {
                        self.cleanup_faulted = true;
                        return false;
                    }
                    self.process_exit_observed = true;
                    self.process_exit_code = Some(exit_code);
                    if self.close_process().is_err() {
                        return false;
                    }
                } else if wait != WAIT_TIMEOUT {
                    self.cleanup_faulted = true;
                    return false;
                } else if let Some(job) = self.job.as_ref().map(OwnedHandle::raw) {
                    // SAFETY: the owned job is the only process-tree boundary;
                    // repeat termination until the parent exit is observed.
                    if unsafe { TerminateJobObject(job, PROVIDER_EXIT_CODE) } == 0 {
                        self.cleanup_faulted = true;
                        return false;
                    }
                }
            } else if self.process.is_some() && self.close_process().is_err() {
                // A prior CloseHandle failure is retried while the owned
                // process reference remains quarantined.
                return false;
            }

            if self.process_exit_observed {
                match self.observe_job_active_processes_once() {
                    Ok(true) => return true,
                    Ok(false) => {}
                    Err(_) => return false,
                }
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.cleanup_faulted = true;
                return false;
            }
            std::thread::sleep(JOB_POLL_INTERVAL.min(remaining));
        }
    }

    pub(super) fn clear_quarantined_fault_after_reap(&mut self) {
        if self.process_exit_observed
            && self.active_processes_zero_observed
            && self.process.is_none()
            && self.job.is_none()
            && self.retained_setup_handles.is_empty()
        {
            self.cleanup_faulted = false;
        }
    }

    pub(super) fn cleanup_faulted(&self) -> bool {
        self.cleanup_faulted
    }

    fn retain_setup_handle(&mut self, handle: OwnedHandle) {
        self.retained_setup_handles.push(handle);
    }
}

pub(super) fn spawn_provider(
    executable: &Path,
    arguments: &[String],
    child_guard: &mut super::ChildGuard,
) -> io::Result<SpawnedProvider> {
    if !executable.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "provider executable path must be absolute",
        ));
    }

    let job = create_kill_on_close_job()?;
    let (child_stdin, parent_stdin) = create_pipe_pair()?;
    let (parent_stdout, child_stdout) = create_pipe_pair()?;
    let (parent_stderr, child_stderr) = create_pipe_pair()?;
    clear_inheritance(parent_stdin.raw())?;
    clear_inheritance(parent_stdout.raw())?;
    clear_inheritance(parent_stderr.raw())?;

    let job_handles = Box::new([job.raw()]);
    let inherited_handles = Box::new([child_stdin.raw(), child_stdout.raw(), child_stderr.raw()]);
    let mut attributes = ProcessAttributeList::new(ATTRIBUTE_COUNT)?;
    attributes.update(
        PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
        job_handles.as_ptr().cast(),
        size_of::<[HANDLE; 1]>(),
    )?;
    attributes.update(
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
        inherited_handles.as_ptr().cast(),
        size_of::<[HANDLE; 3]>(),
    )?;

    let application_name = nul_terminated_wide(executable.as_os_str())?;
    let mut command_line = build_command_line(executable.as_os_str(), arguments)?;
    let mut startup: STARTUPINFOEXW = zeroed_value();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = child_stdin.raw();
    startup.StartupInfo.hStdOutput = child_stdout.raw();
    startup.StartupInfo.hStdError = child_stderr.raw();
    startup.lpAttributeList = attributes.raw();

    let mut retained_setup_handles = Vec::new();
    retained_setup_handles
        .try_reserve_exact(MAX_RETAINED_SETUP_HANDLES)
        .map_err(|error| {
            io::Error::other(format!(
                "setup-handle quarantine allocation failed: {error}"
            ))
        })?;

    let mut process_info: PROCESS_INFORMATION = zeroed_value();
    // SAFETY: every pointer below targets initialized, NUL-terminated or
    // correctly sized storage kept alive until CreateProcessW returns. The
    // explicit HANDLE_LIST contains only the three child stdio pipe ends;
    // JOB_LIST atomically assigns the child before its initial thread runs.
    let created = unsafe {
        windows_sys::Win32::System::Threading::CreateProcessW(
            application_name.as_ptr(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
            null(),
            null(),
            &startup.StartupInfo,
            &mut process_info,
        )
    };
    if created == 0 {
        let error = io::Error::last_os_error();
        // Microsoft documents only the return status on failure; it does not
        // promise valid PROCESS_INFORMATION outputs. Do not inspect or wrap
        // either handle slot. The local job and pipe owners unwind normally.
        return Err(error);
    }

    // Take both CreateProcessW output handles before any further fallible
    // cleanup so a later error cannot leak either the process or thread.
    let process_owner = OwnedHandle::from_raw(process_info.hProcess);
    let process_valid = process_owner.is_valid();
    let process = if process_valid {
        Some(process_owner)
    } else {
        drop(process_owner);
        None
    };
    let mut primary_thread = OwnedHandle::from_raw(process_info.hThread);
    let thread_valid = primary_thread.is_valid();
    let native_child = NativeChild {
        process,
        job: Some(job),
        process_exit_observed: false,
        process_exit_code: None,
        active_processes_zero_observed: false,
        cleanup_faulted: false,
        retained_setup_handles,
    };
    // The parent-owned guard takes process/job lifetime responsibility before
    // any further fallible handle closing or stdio conversion happens.
    child_guard.attach_child(native_child);
    let mut setup_error = None;
    if thread_valid {
        if let Err(error) = close_setup_handle(primary_thread, child_guard) {
            setup_error = Some(error);
        }
    }
    for handle in [child_stdin, child_stdout, child_stderr] {
        if let Err(error) = close_setup_handle(handle, child_guard) {
            if setup_error.is_none() {
                setup_error = Some(error);
            }
        }
    }
    if let Some(error) = setup_error {
        return Err(error);
    }
    if !process_valid || !thread_valid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CreateProcessW returned an invalid process/thread handle",
        ));
    }
    drop(attributes);
    drop(job_handles);
    drop(inherited_handles);

    let stdin = unsafe_file_from_handle(parent_stdin)?;
    let stdout = unsafe_file_from_handle(parent_stdout)?;
    let stderr = unsafe_file_from_handle(parent_stderr)?;

    Ok(SpawnedProvider {
        stdin,
        stdout,
        stderr,
    })
}

pub(super) fn cancel_synchronous_io(thread: &JoinHandle<()>) {
    let handle = thread.as_raw_handle() as HANDLE;
    // SAFETY: Rust 1.100's Windows JoinHandle raw handle is the CreateThread
    // handle (THREAD_ALL_ACCESS); the JoinHandle remains retained through join
    // or quarantine. THREAD_TERMINATE is required, and cancellation only
    // requests that this helper's synchronous pipe I/O stop.
    let _ = unsafe { CancelSynchronousIo(handle) };
}

fn create_kill_on_close_job() -> io::Result<OwnedHandle> {
    // SAFETY: null security attributes create a private, non-inheritable job.
    let raw = unsafe { CreateJobObjectW(null(), null()) };
    let mut job = OwnedHandle::new(raw)?;
    // Defense-in-depth: keep the Job Object out of all child handle tables.
    clear_inheritance(job.raw())?;

    // SAFETY: zero is the documented neutral initialization for this C ABI
    // structure; every native limit flag remains unset except kill-on-close.
    let mut information: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: the pointer and exact structure size match the information class.
    if unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            (&information as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(job)
}

fn create_pipe_pair() -> io::Result<(OwnedHandle, OwnedHandle)> {
    let mut security = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    // windows-sys 0.52 aliases HANDLE to isize, with 0 as the null handle.
    let mut read: HANDLE = 0;
    let mut write: HANDLE = 0;
    // SAFETY: outputs are writable HANDLE slots and security describes an
    // inheritable anonymous pipe. The HANDLE_LIST later limits inheritance.
    if unsafe { CreatePipe(&mut read, &mut write, &mut security, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let read = OwnedHandle::from_raw(read);
    let write = OwnedHandle::from_raw(write);
    if !read.is_valid() || !write.is_valid() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CreatePipe returned an invalid pipe handle",
        ));
    }
    Ok((read, write))
}

fn clear_inheritance(handle: HANDLE) -> io::Result<()> {
    // SAFETY: `handle` is an owned valid pipe/job handle; mask the inherit bit
    // and clear it so only the explicit startup handle list reaches the child.
    if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn close_setup_handle(
    mut handle: OwnedHandle,
    child_guard: &mut super::ChildGuard,
) -> io::Result<()> {
    match handle.close_checked() {
        Ok(()) => Ok(()),
        Err(error) => {
            let Some(child) = child_guard.child.as_mut() else {
                return Err(io::Error::other(format!(
                    "provider handle close failed before child ownership: {error}"
                )));
            };
            child.retain_setup_handle(handle);
            Err(error)
        }
    }
}

struct ProcessAttributeList {
    storage: Vec<usize>,
    initialized: bool,
}

impl ProcessAttributeList {
    fn new(attribute_count: u32) -> io::Result<Self> {
        let mut required_bytes = 0usize;
        // SAFETY: the documented sizing call uses a null list and writable size.
        let sizing_result = unsafe {
            InitializeProcThreadAttributeList(null_mut(), attribute_count, 0, &mut required_bytes)
        };
        if sizing_result != 0 || required_bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "attribute-list sizing call returned an invalid size",
            ));
        }
        // SAFETY: GetLastError is thread-local and follows the sizing call
        // without another Windows API call that could overwrite it.
        let sizing_error = unsafe { GetLastError() };
        if sizing_error != ERROR_INSUFFICIENT_BUFFER {
            return Err(io::Error::from_raw_os_error(sizing_error as i32));
        }
        let word = size_of::<usize>();
        let word_count = required_bytes
            .checked_add(word - 1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "attribute size overflow"))?
            / word;
        let mut storage = Vec::<usize>::new();
        storage.try_reserve_exact(word_count).map_err(|error| {
            io::Error::other(format!("attribute-list allocation failed: {error}"))
        })?;
        storage.resize(word_count, 0);
        let list = storage.as_mut_ptr().cast::<c_void>();
        // SAFETY: storage has sufficient byte size and natural usize alignment.
        if unsafe {
            InitializeProcThreadAttributeList(list, attribute_count, 0, &mut required_bytes)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            storage,
            initialized: true,
        })
    }

    fn raw(&mut self) -> *mut c_void {
        self.storage.as_mut_ptr().cast::<c_void>()
    }

    fn update(&mut self, attribute: usize, value: *const c_void, size: usize) -> io::Result<()> {
        // SAFETY: `list` was initialized and the caller keeps `value` stable
        // through the subsequent CreateProcessW and attribute-list deletion.
        let list = self.storage.as_mut_ptr().cast::<c_void>();
        if unsafe { UpdateProcThreadAttribute(list, 0, attribute, value, size, null_mut(), null()) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for ProcessAttributeList {
    fn drop(&mut self) {
        if self.initialized {
            // SAFETY: list storage remains alive until after this destructor
            // body, and DeleteProcThreadAttributeList is called exactly once.
            let list = self.storage.as_mut_ptr().cast::<c_void>();
            unsafe { windows_sys::Win32::System::Threading::DeleteProcThreadAttributeList(list) };
            self.initialized = false;
        }
    }
}

struct OwnedHandle {
    handle: Option<HANDLE>,
}

// SAFETY: HANDLE values are process-wide kernel references; ownership is
// unique, and CloseHandle/Job Object operations are not thread-affine.
unsafe impl Send for OwnedHandle {}

impl OwnedHandle {
    fn new(handle: HANDLE) -> io::Result<Self> {
        let owner = Self::from_raw(handle);
        if !owner.is_valid() {
            return Err(io::Error::last_os_error());
        }
        Ok(owner)
    }

    fn from_raw(handle: HANDLE) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    fn is_valid(&self) -> bool {
        self.handle
            .is_some_and(|handle| handle != 0 && handle != -1)
    }

    fn raw(&self) -> HANDLE {
        self.handle
            .filter(|handle| *handle != 0 && *handle != -1)
            .expect("owned handle remains open and valid")
    }

    fn into_raw(mut self) -> HANDLE {
        self.handle
            .take()
            .filter(|handle| *handle != 0 && *handle != -1)
            .expect("owned handle remains open and valid")
    }

    fn close_checked(&mut self) -> io::Result<()> {
        let Some(handle) = self.handle else {
            return Ok(());
        };
        if handle == 0 || handle == -1 {
            self.handle = None;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid handle",
            ));
        }
        // SAFETY: this owner is the unique Rust owner of `handle`.
        if unsafe { CloseHandle(handle) } == 0 {
            return Err(io::Error::last_os_error());
        }
        self.handle = None;
        Ok(())
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        let _ = self.close_checked();
    }
}

fn unsafe_file_from_handle(handle: OwnedHandle) -> io::Result<File> {
    let raw = handle.into_raw();
    // SAFETY: the unique raw HANDLE ownership is transferred to File and will
    // be closed by its Drop; the pipe endpoint is a synchronous byte stream.
    Ok(unsafe { File::from_raw_handle(raw as RawHandle) })
}

fn nul_terminated_wide(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut wide = value.encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows process strings cannot contain NUL",
        ));
    }
    wide.push(0);
    Ok(wide)
}

fn build_command_line(executable: &OsStr, arguments: &[String]) -> io::Result<Vec<u16>> {
    let mut command_line = Vec::new();
    append_quoted_argument(&mut command_line, executable)?;
    for argument in arguments {
        command_line.push(b' ' as u16);
        append_quoted_argument(&mut command_line, OsStr::new(argument))?;
    }
    if command_line.len() >= 32_767 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows process command line exceeds 32766 UTF-16 units",
        ));
    }
    command_line.push(0);
    Ok(command_line)
}

fn append_quoted_argument(output: &mut Vec<u16>, value: &OsStr) -> io::Result<()> {
    let units = value.encode_wide().collect::<Vec<_>>();
    if units.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows process arguments cannot contain NUL",
        ));
    }
    output.push(b'"' as u16);
    let mut backslashes = 0usize;
    for unit in units {
        if unit == b'\\' as u16 {
            backslashes += 1;
            continue;
        }
        if unit == b'"' as u16 {
            output.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
            output.push(unit);
        } else {
            output.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
            output.push(unit);
        }
        backslashes = 0;
    }
    output.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
    output.push(b'"' as u16);
    Ok(())
}

fn duration_to_millis(duration: Duration) -> u32 {
    duration.as_millis().min(u128::from(u32::MAX)) as u32
}

fn cleanup_complete(
    process_exit_observed: bool,
    process_handle_open: bool,
    job_handle_open: bool,
    active_processes_zero_observed: bool,
) -> bool {
    process_exit_observed
        && !process_handle_open
        && !job_handle_open
        && active_processes_zero_observed
}

fn process_wait_confirms_exit(wait_status: u32) -> bool {
    wait_status == WAIT_OBJECT_0
}

fn zeroed_value<T>() -> T {
    // SAFETY: callers use this only for Windows ABI structs whose zeroed form
    // is a valid neutral initialization before explicit fields are assigned.
    unsafe { zeroed() }
}

#[cfg(test)]
mod tests {
    use super::{WAIT_OBJECT_0, WAIT_TIMEOUT, cleanup_complete, process_wait_confirms_exit};

    #[test]
    fn cleanup_requires_parent_exit_zero_count_and_closed_handles() {
        assert!(!cleanup_complete(false, false, false, true));
        assert!(!cleanup_complete(true, false, false, false));
        assert!(!cleanup_complete(true, true, false, true));
        assert!(!cleanup_complete(true, false, true, true));
        assert!(cleanup_complete(true, false, false, true));
        assert!(!process_wait_confirms_exit(WAIT_TIMEOUT));
        assert!(process_wait_confirms_exit(WAIT_OBJECT_0));
    }
}
