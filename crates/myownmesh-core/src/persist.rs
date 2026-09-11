//! Crash-safe persistence primitives for MyOwnMesh's state files.
//!
//! Every durable file the engine owns (config, rosters, custody store,
//! identity anchor) used to be written with a
//! plain truncate-and-write. On an appliance that loses power — or a
//! daemon killed mid-write — that leaves a 0-byte file behind, and a
//! file that *exists but doesn't parse* used to fail hard forever:
//! a KVM was found bricked off its fleet by exactly this (an empty
//! roster file failing every subsequent join). Two primitives close
//! both halves:
//!
//! * [`write_atomic`] — write-to-temp + fsync + rename, so a file is
//!   only ever its previous complete contents or its next complete
//!   contents, never a truncation. The fsync before the rename
//!   matters on the FAT-style filesystems small devices keep state
//!   on; without it the rename can land before the data does.
//! * [`quarantine`] — shove a corrupt file aside (`{name}.corrupt`)
//!   instead of deleting it, so loaders can fall back to a fresh
//!   default *without destroying the evidence* (or a hand-editor's
//!   work). Loaders that fall back this way must log loudly.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

impl DirectoryCapability {
    /// Acquire an explicitly caller-selected storage root. Only its parent
    /// namespace is selection input: Unix may resolve aliases there (for
    /// example an OS temporary-directory ancestor). Never pass a managed
    /// descendant such as mesh/rosters, a network id, or a transaction here.
    /// The root leaf and all subsequently opened children remain no-follow.
    /// After selection, even parent traversal uses the strict handle walker;
    /// no pathname fallback follows a refused leaf or managed descendant.
    pub(crate) fn open_selected_root(path: &Path, create: bool) -> std::io::Result<Self> {
        if !path.is_absolute()
            || path.file_name().is_none()
            || path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "selected storage root requires an absolute non-root path without traversal",
            ));
        }
        #[cfg(unix)]
        {
            // Validate the whole selected spelling before opening or creating
            // anything, including a missing parent suffix.
            for part in path.components() {
                if let std::path::Component::Normal(name) = part {
                    let name = name.to_str().ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "directory component is not UTF-8",
                        )
                    })?;
                    component(name)?;
                }
            }
            let mut anchor = path.parent().expect("validated non-root absolute path");
            loop {
                match std::fs::symlink_metadata(anchor) {
                    Ok(_) => break,
                    Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                        anchor = anchor.parent().ok_or(error)?;
                    }
                    Err(error) => return Err(error),
                }
            }
            // Canonicalize only the existing selected PARENT anchor, never
            // the root leaf. A dangling alias fails here rather than falling
            // back to creation through its target.
            let selected_parent = std::fs::canonicalize(anchor)?;
            let mut current = Self::open_path(&selected_parent, false)?;
            let suffix = path
                .strip_prefix(anchor)
                .expect("anchor is a lexical ancestor");
            for part in suffix.components() {
                if let std::path::Component::Normal(name) = part {
                    current = current.open_dir(name.to_str().expect("validated UTF-8"), create)?;
                }
            }
            Ok(current)
        }
        #[cfg(not(unix))]
        {
            // Preserve the Windows reparse/relative-handle implementation
            // and the unsupported-platform refusal without a new fallback.
            Self::open_path(path, create)
        }
    }
}

/// A retained directory capability used by keyed roster persistence.
///
/// The capability is deliberately narrower than a general filesystem API:
/// callers can only name one component at a time, and all operations are
/// relative to the held directory descriptor/handle.  This prevents a
/// parent rename or replacement after acquisition from redirecting a write
/// into an attacker-selected tree.
#[cfg(unix)]
pub(crate) struct DirectoryCapability {
    fd: std::os::fd::OwnedFd,
}

#[cfg(unix)]
impl DirectoryCapability {
    pub(crate) fn open_path(path: &Path, create: bool) -> std::io::Result<Self> {
        use std::os::fd::FromRawFd;

        if !path.is_absolute() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "directory capability requires an absolute path",
            ));
        }
        let root = std::ffi::CString::new("/").expect("literal has no NUL");
        let raw = unsafe {
            libc::open(
                root.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut current = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        for component in path.components() {
            let component = match component {
                std::path::Component::RootDir | std::path::Component::CurDir => continue,
                std::path::Component::Normal(component) => component,
                std::path::Component::ParentDir | std::path::Component::Prefix(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "directory capability path contains traversal",
                    ));
                }
            };
            let name = component.to_str().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "directory component is not UTF-8",
                )
            })?;
            current = open_child(&current, name, create)?;
        }
        Ok(Self { fd: current })
    }

    pub(crate) fn open_dir(&self, name: &str, create: bool) -> std::io::Result<Self> {
        Ok(Self {
            fd: open_child(&self.fd, name, create)?,
        })
    }

    pub(crate) fn read_names_bounded(
        &self,
        max_entries: usize,
        max_name_bytes: usize,
    ) -> std::io::Result<Vec<String>> {
        use std::os::fd::AsRawFd;

        let duplicate = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let directory = unsafe { libc::fdopendir(duplicate) };
        if directory.is_null() {
            unsafe { libc::close(duplicate) };
            return Err(std::io::Error::last_os_error());
        }
        let result = (|| -> std::io::Result<Vec<String>> {
            let mut names = Vec::new();
            loop {
                clear_readdir_errno();
                let entry = unsafe { libc::readdir(directory) };
                if entry.is_null() {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error().unwrap_or(0) == 0 {
                        break;
                    }
                    return Err(error);
                }
                let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
                if name.to_bytes() == b"." || name.to_bytes() == b".." {
                    continue;
                }
                if name.to_bytes().len() > max_name_bytes || names.len() >= max_entries {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "directory entry bound exceeded",
                    ));
                }
                let name = name.to_str().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "directory entry is not UTF-8",
                    )
                })?;
                names.push(name.to_owned());
            }
            Ok(names)
        })();
        let close_result = unsafe { libc::closedir(directory) };
        match result {
            Err(error) => Err(error),
            Ok(names) if close_result == 0 => Ok(names),
            Ok(_) => Err(std::io::Error::last_os_error()),
        }
    }

    pub(crate) fn read_file(&self, name: &str, limit: usize) -> std::io::Result<Vec<u8>> {
        let mut file = self.open_file(name, false)?;
        let mut bytes = Vec::with_capacity(limit.min(4096));
        std::io::Read::by_ref(&mut file)
            .take(limit.saturating_add(1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "file exceeds capability read limit",
            ));
        }
        Ok(bytes)
    }

    pub(crate) fn write_new(&self, name: &str, bytes: &[u8], mode: u32) -> std::io::Result<()> {
        use std::os::fd::{AsRawFd, FromRawFd};

        let name = component(name)?;
        let raw = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                mode as libc::mode_t as libc::c_uint,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut file = unsafe { std::fs::File::from_raw_fd(raw) };
        file.write_all(bytes)?;
        file.sync_all()
    }

    pub(crate) fn open_file(&self, name: &str, write: bool) -> std::io::Result<std::fs::File> {
        use std::os::fd::{AsRawFd, FromRawFd};

        let name = component(name)?;
        ensure_regular_source(&self.fd, &name)?;
        let flags =
            if write { libc::O_RDWR } else { libc::O_RDONLY } | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        let raw = unsafe { libc::openat(self.fd.as_raw_fd(), name.as_ptr(), flags) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { std::fs::File::from_raw_fd(raw) })
    }

    pub(crate) fn rename_to(
        &self,
        from: &str,
        destination: &Self,
        to: &str,
    ) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        let from = component(from)?;
        let to = component(to)?;
        ensure_regular_source(&self.fd, &from)?;
        ensure_regular_or_absent(&destination.fd, &to)?;
        let result = unsafe {
            libc::renameat(
                self.fd.as_raw_fd(),
                from.as_ptr(),
                destination.fd.as_raw_fd(),
                to.as_ptr(),
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    pub(crate) fn remove_file(&self, name: &str) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        let name = component(name)?;
        ensure_regular_source(&self.fd, &name).or_else(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(error)
            }
        })?;
        let result = unsafe { libc::unlinkat(self.fd.as_raw_fd(), name.as_ptr(), 0) };
        if result == 0 {
            Ok(())
        } else {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(error)
            }
        }
    }

    pub(crate) fn quarantine(&self, name: &str) -> std::io::Result<()> {
        let destination = format!("{name}.corrupt");
        self.rename_to(name, self, &destination)
    }

    pub(crate) fn remove_tree(&self, name: &str) -> std::io::Result<()> {
        remove_tree_at(&self.fd, name)
    }

    pub(crate) fn sync(&self) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        if unsafe { libc::fsync(self.fd.as_raw_fd()) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

#[cfg(unix)]
fn clear_readdir_errno() {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    unsafe {
        *libc::__errno_location() = 0;
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    unsafe {
        *libc::__error() = 0;
    }
}

#[cfg(unix)]
fn component(name: &str) -> std::io::Result<std::ffi::CString> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "directory capability component is invalid",
        ));
    }
    std::ffi::CString::new(name).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "directory capability component contains NUL",
        )
    })
}

#[cfg(unix)]
fn open_child(
    parent: &std::os::fd::OwnedFd,
    name: &str,
    create: bool,
) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = component(name)?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    let mut raw = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if raw < 0 && create && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        }
        raw = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    }
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) })
}

#[cfg(unix)]
fn ensure_regular_source(
    directory: &std::os::fd::OwnedFd,
    name: &std::ffi::CStr,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let stat = unsafe { stat.assume_init() };
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "refusing a non-regular or reparse roster entry",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_regular_or_absent(
    directory: &std::os::fd::OwnedFd,
    name: &std::ffi::CStr,
) -> std::io::Result<()> {
    match ensure_regular_source(directory, name) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn remove_tree_at(parent: &std::os::fd::OwnedFd, name: &str) -> std::io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let name = component(name)?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    let child = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if child < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(());
        }
        if error.raw_os_error() == Some(libc::ENOTDIR) {
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            if unsafe {
                libc::fstatat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    stat.as_mut_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let stat = unsafe { stat.assume_init() };
            if (stat.st_mode & libc::S_IFMT) == libc::S_IFLNK {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "refusing to recursively delete a reparse entry",
                ));
            }
            let result = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) };
            return if result == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            };
        }
        return Err(error);
    }
    let child = unsafe { std::os::fd::OwnedFd::from_raw_fd(child) };
    for entry in (DirectoryCapability {
        fd: child.try_clone()?,
    })
    .read_names_bounded(4096, 512)?
    {
        let child_name = component(&entry)?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                child.as_raw_fd(),
                child_name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let stat = unsafe { stat.assume_init() };
        if (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            remove_tree_at(&child, &entry)?;
        } else if (stat.st_mode & libc::S_IFMT) == libc::S_IFLNK {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "refusing to recursively delete a reparse entry",
            ));
        } else if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "refusing to recursively delete a non-regular roster entry",
            ));
        } else if unsafe { libc::unlinkat(child.as_raw_fd(), child_name.as_ptr(), 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
mod windows_directory {
    use super::*;
    use std::ffi::c_void;
    use std::mem::{size_of, MaybeUninit};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle, RawHandle};
    use std::path::{Component, Prefix};
    use std::ptr::null_mut;

    type Handle = RawHandle;
    type NtStatus = i32;

    const STATUS_SUCCESS: NtStatus = 0;
    const STATUS_NO_MORE_FILES: NtStatus = 0x8000_0006u32 as i32;
    const STATUS_OBJECT_NAME_NOT_FOUND: NtStatus = 0xC000_0034u32 as i32;
    const STATUS_OBJECT_NAME_INVALID: NtStatus = 0xC000_0033u32 as i32;
    const STATUS_OBJECT_PATH_NOT_FOUND: NtStatus = 0xC000_003Au32 as i32;
    const STATUS_NO_SUCH_FILE: NtStatus = 0xC000_000Fu32 as i32;
    const STATUS_INVALID_PARAMETER: NtStatus = 0xC000_000Du32 as i32;
    const STATUS_ACCESS_DENIED: NtStatus = 0xC000_0022u32 as i32;
    const STATUS_SHARING_VIOLATION: NtStatus = 0xC000_0043u32 as i32;
    const STATUS_IO_REPARSE_TAG_NOT_HANDLED: NtStatus = 0xC000_0279u32 as i32;
    const STATUS_REPARSE_POINT_ENCOUNTERED: NtStatus = 0xC000_050Bu32 as i32;
    const STATUS_OBJECT_NAME_COLLISION: NtStatus = 0xC000_0035u32 as i32;
    const STATUS_NOT_A_DIRECTORY: NtStatus = 0xC000_0103u32 as i32;
    const STATUS_FILE_IS_A_DIRECTORY: NtStatus = 0xC000_00BAu32 as i32;
    const STATUS_BUFFER_OVERFLOW: NtStatus = 0x8000_0005u32 as i32;

    const FILE_READ_DATA: u32 = 0x0001;
    const FILE_WRITE_DATA: u32 = 0x0002;
    const FILE_APPEND_DATA: u32 = 0x0004;
    const FILE_LIST_DIRECTORY: u32 = 0x0001;
    const FILE_ADD_FILE: u32 = 0x0002;
    const FILE_ADD_SUBDIRECTORY: u32 = 0x0004;
    const FILE_TRAVERSE: u32 = 0x0020;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
    const DELETE: u32 = 0x0001_0000;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const SHARE_READ: u32 = 0x0001;
    const SHARE_WRITE: u32 = 0x0002;
    const SHARE_DELETE: u32 = 0x0004;
    const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
    const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
    const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
    const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_OPEN_FOR_BACKUP_INTENT: u32 = 0x0000_4000;
    const FILE_OPEN: u32 = 1;
    const FILE_CREATE: u32 = 2;
    const FILE_OPEN_IF: u32 = 3;
    const WIN32_OPEN_EXISTING: u32 = 3;
    const OBJ_CASE_INSENSITIVE: u32 = 0x40;
    const OBJ_DONT_REPARSE: u32 = 0x1000;
    const FILE_DIRECTORY_INFORMATION: u32 = 1;
    const FILE_RENAME_INFORMATION: u32 = 10;
    const FILE_DISPOSITION_INFORMATION: u32 = 13;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    const FILE_INFO_BY_HANDLE_FILE_ATTRIBUTE_TAG_INFO: u32 = 9;

    #[allow(dead_code)]
    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    #[allow(dead_code)]
    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root_directory: Handle,
        object_name: *mut UnicodeString,
        attributes: u32,
        security_descriptor: *mut c_void,
        security_quality_of_service: *mut c_void,
    }

    #[allow(dead_code)]
    #[repr(C)]
    struct IoStatusBlock {
        status: NtStatus,
        information: usize,
    }

    #[allow(dead_code)]
    #[repr(C)]
    struct FileAttributeTagInformation {
        file_attributes: u32,
        reparse_tag: u32,
    }

    #[allow(dead_code)]
    #[derive(Clone, Copy)]
    #[repr(C)]
    struct FileDirectoryInformationHeader {
        next_entry_offset: u32,
        file_index: u32,
        creation_time: i64,
        last_access_time: i64,
        last_write_time: i64,
        change_time: i64,
        end_of_file: i64,
        allocation_size: i64,
        file_attributes: u32,
        file_name_length: u32,
    }

    #[repr(C)]
    struct FileRenameInformationHeader {
        replace_if_exists: u8,
        root_directory: Handle,
        file_name_length: u32,
    }

    #[allow(dead_code)]
    #[repr(C)]
    struct FileDispositionInformation {
        delete_file: u8,
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn NtCreateFile(
            file_handle: *mut Handle,
            desired_access: u32,
            object_attributes: *mut ObjectAttributes,
            io_status_block: *mut IoStatusBlock,
            allocation_size: *mut i64,
            file_attributes: u32,
            share_access: u32,
            create_disposition: u32,
            create_options: u32,
            ea_buffer: *mut c_void,
            ea_length: u32,
        ) -> NtStatus;
        fn NtSetInformationFile(
            file_handle: Handle,
            io_status_block: *mut IoStatusBlock,
            file_information: *mut c_void,
            length: u32,
            file_information_class: u32,
        ) -> NtStatus;
        fn NtQueryDirectoryFile(
            file_handle: Handle,
            event: Handle,
            apc_routine: *mut c_void,
            apc_context: *mut c_void,
            io_status_block: *mut IoStatusBlock,
            file_information: *mut c_void,
            length: u32,
            file_information_class: u32,
            return_single_entry: u8,
            file_name: *mut UnicodeString,
            restart_scan: u8,
        ) -> NtStatus;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileW(
            file_name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *mut c_void,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: Handle,
        ) -> Handle;
        fn GetFileInformationByHandleEx(
            file: Handle,
            file_information_class: u32,
            file_information: *mut c_void,
            buffer_size: u32,
        ) -> i32;
    }

    fn io_error(status: NtStatus) -> std::io::Error {
        let kind = match status {
            STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND | STATUS_NO_SUCH_FILE => {
                std::io::ErrorKind::NotFound
            }
            STATUS_OBJECT_NAME_COLLISION => std::io::ErrorKind::AlreadyExists,
            STATUS_OBJECT_NAME_INVALID | STATUS_INVALID_PARAMETER => {
                std::io::ErrorKind::InvalidInput
            }
            STATUS_ACCESS_DENIED
            | STATUS_IO_REPARSE_TAG_NOT_HANDLED
            | STATUS_REPARSE_POINT_ENCOUNTERED => std::io::ErrorKind::PermissionDenied,
            STATUS_SHARING_VIOLATION => std::io::ErrorKind::PermissionDenied,
            STATUS_NOT_A_DIRECTORY => std::io::ErrorKind::NotADirectory,
            STATUS_FILE_IS_A_DIRECTORY => std::io::ErrorKind::IsADirectory,
            _ => std::io::ErrorKind::Other,
        };
        std::io::Error::new(
            kind,
            format!("Windows native roster operation failed: NTSTATUS {status:#x}"),
        )
    }

    fn status_result(syscall_status: NtStatus, io_status: NtStatus) -> std::io::Result<()> {
        if syscall_status != STATUS_SUCCESS {
            return Err(io_error(syscall_status));
        }
        if io_status != STATUS_SUCCESS {
            return Err(io_error(io_status));
        }
        Ok(())
    }

    fn stage_error(
        stage: &str,
        index: Option<usize>,
        component: Option<&[u16]>,
        error: std::io::Error,
    ) -> std::io::Error {
        let component = component
            .map(|value| {
                format!(
                    "component_index={} component_name={}",
                    index.map_or_else(|| "-".into(), |value| value.to_string()),
                    String::from_utf16_lossy(value)
                )
            })
            .unwrap_or_else(|| "component=drive_root".into());
        let native = error
            .raw_os_error()
            .map_or_else(|| "none".into(), |value| value.to_string());
        std::io::Error::new(
            error.kind(),
            format!("Windows roster {stage} ({component}, native_error={native}): {error}"),
        )
    }

    fn component(name: &str) -> std::io::Result<Vec<u16>> {
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', '\0']) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "roster path component is not a single safe name",
            ));
        }
        let value: Vec<u16> = std::ffi::OsStr::new(name).encode_wide().collect();
        if value.is_empty() || value.len() > (u16::MAX as usize / 2) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "roster path component is not representable",
            ));
        }
        Ok(value)
    }

    fn wide_path(path: &Path) -> std::io::Result<(Vec<u16>, Vec<Vec<u16>>)> {
        let mut components = path.components();
        let drive = match components.next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(letter) => char::from_u32(letter as u32).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid Windows drive")
                })?,
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "UNC and device roster paths are unsupported",
                    ))
                }
            },
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "roster capability requires an absolute drive path",
                ))
            }
        };
        if !matches!(components.next(), Some(Component::RootDir)) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "roster capability requires a rooted drive path",
            ));
        }
        let mut root: Vec<u16> = format!("{drive}:\\").encode_utf16().collect();
        root.push(0);
        let mut names = Vec::new();
        for item in components {
            let Component::Normal(name) = item else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "roster capability rejects non-normal path components",
                ));
            };
            let value = name.to_str().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "non-Unicode roster path")
            })?;
            names.push(component(value)?);
        }
        Ok((root, names))
    }

    fn reject_reparse(handle: Handle) -> std::io::Result<()> {
        let mut info = MaybeUninit::<FileAttributeTagInformation>::zeroed();
        let ok = unsafe {
            GetFileInformationByHandleEx(
                handle,
                FILE_INFO_BY_HANDLE_FILE_ATTRIBUTE_TAG_INFO,
                info.as_mut_ptr().cast(),
                size_of::<FileAttributeTagInformation>() as u32,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let info = unsafe { info.assume_init() };
        if info.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "roster capability refuses a reparse point",
            ));
        }
        Ok(())
    }

    fn open_relative(
        parent: Handle,
        name: &[u16],
        create: bool,
        directory: bool,
        exclusive: bool,
    ) -> std::io::Result<OwnedHandle> {
        open_relative_with_access(
            parent,
            name,
            create,
            directory,
            exclusive,
            directory,
            create && directory,
            false,
            !directory && exclusive,
            false,
        )
    }

    // The access booleans mirror the native NtCreateFile boundary; bundling
    // them would obscure the exact lease and reparse-point permissions.
    #[allow(clippy::too_many_arguments)]
    fn open_relative_with_access(
        parent: Handle,
        name: &[u16],
        create: bool,
        directory: bool,
        exclusive: bool,
        list_directory: bool,
        child_creation: bool,
        delete_self: bool,
        write_file: bool,
        delete_file: bool,
    ) -> std::io::Result<OwnedHandle> {
        let mut name = name.to_vec();
        let mut unicode = UnicodeString {
            length: (name.len() * 2) as u16,
            maximum_length: (name.len() * 2) as u16,
            buffer: name.as_mut_ptr(),
        };
        let mut attrs = ObjectAttributes {
            length: size_of::<ObjectAttributes>() as u32,
            root_directory: parent,
            object_name: &mut unicode,
            attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
            security_descriptor: null_mut(),
            security_quality_of_service: null_mut(),
        };
        let mut raw: Handle = null_mut();
        let mut status_block = IoStatusBlock {
            status: STATUS_SUCCESS,
            information: 0,
        };
        let desired = if directory {
            (if list_directory {
                FILE_LIST_DIRECTORY
            } else {
                0
            }) | FILE_TRAVERSE
                | FILE_READ_ATTRIBUTES
                | SYNCHRONIZE
                | if child_creation {
                    FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY
                } else {
                    0
                }
                | if delete_self { DELETE } else { 0 }
        } else {
            FILE_READ_DATA
                | FILE_READ_ATTRIBUTES
                | SYNCHRONIZE
                | if write_file {
                    FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES
                } else {
                    0
                }
                | if delete_file { DELETE } else { 0 }
        };
        let options = if directory {
            FILE_DIRECTORY_FILE
        } else {
            FILE_NON_DIRECTORY_FILE
        } | FILE_SYNCHRONOUS_IO_NONALERT
            | FILE_OPEN_REPARSE_POINT
            | FILE_OPEN_FOR_BACKUP_INTENT;
        let disposition = if exclusive {
            FILE_CREATE
        } else if create {
            FILE_OPEN_IF
        } else {
            FILE_OPEN
        };
        let status = unsafe {
            NtCreateFile(
                &mut raw,
                desired,
                &mut attrs,
                &mut status_block,
                null_mut(),
                0,
                SHARE_READ | SHARE_WRITE | SHARE_DELETE,
                disposition,
                options,
                null_mut(),
                0,
            )
        };
        status_result(status, status_block.status)?;
        if raw.is_null() {
            return Err(std::io::Error::other(
                "Windows native roster open returned a null handle",
            ));
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        reject_reparse(handle.as_raw_handle())?;
        Ok(handle)
    }

    fn reopen_parent_for_creation(
        root: Handle,
        existing: &[Vec<u16>],
    ) -> std::io::Result<OwnedHandle> {
        let Some((last, prefix)) = existing.split_last() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "roster capability refuses creation directly under a drive root",
            ));
        };
        let mut parent = root;
        let mut retained = None;
        for name in prefix {
            let next = open_relative_with_access(
                parent, name, false, true, false, false, false, false, false, false,
            )?;
            parent = next.as_raw_handle();
            retained = Some(next);
        }
        let next = open_relative_with_access(
            parent, last, false, true, false, false, true, false, false, false,
        )?;
        drop(retained);
        Ok(next)
    }

    fn open_drive_root(root: &[u16]) -> std::io::Result<OwnedHandle> {
        let raw = unsafe {
            CreateFileW(
                root.as_ptr(),
                FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                SHARE_READ | SHARE_WRITE | SHARE_DELETE,
                null_mut(),
                WIN32_OPEN_EXISTING,
                0x0200_0000 | 0x0020_0000,
                null_mut(),
            )
        };
        if raw == (-1isize) as Handle || raw.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        reject_reparse(handle.as_raw_handle())?;
        Ok(handle)
    }

    fn open_dir_handle(parent: Handle, name: &str, create: bool) -> std::io::Result<OwnedHandle> {
        let name = component(name)?;
        if create {
            match open_relative_with_access(
                parent, &name, false, true, false, true, true, false, false, false,
            ) {
                Ok(handle) => Ok(handle),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    open_relative_with_access(
                        parent, &name, true, true, false, true, true, false, false, false,
                    )
                }
                Err(error) => Err(error),
            }
        } else {
            open_relative_with_access(
                parent, &name, false, true, false, true, false, false, false, false,
            )
        }
    }

    fn remove_directory(parent: Handle, name: &str) -> std::io::Result<()> {
        let child = open_relative_with_access(
            parent,
            &component(name)?,
            false,
            true,
            false,
            false,
            false,
            true,
            false,
            false,
        )?;
        let mut info = IoStatusBlock {
            status: STATUS_SUCCESS,
            information: 0,
        };
        let mut disposition = FileDispositionInformation { delete_file: 1 };
        let status = unsafe {
            NtSetInformationFile(
                child.as_raw_handle(),
                &mut info,
                (&mut disposition as *mut FileDispositionInformation).cast(),
                size_of::<FileDispositionInformation>() as u32,
                FILE_DISPOSITION_INFORMATION,
            )
        };
        status_result(status, info.status)
    }

    fn remove_tree_at(parent: Handle, name: &str) -> std::io::Result<()> {
        let child = open_relative_with_access(
            parent,
            &component(name)?,
            false,
            true,
            false,
            true,
            false,
            false,
            false,
            true,
        )?;
        let names = read_names_handle(child.as_raw_handle(), 4096, 512)?;
        for entry in names {
            if entry == "." || entry == ".." {
                continue;
            }
            match remove_tree_at(child.as_raw_handle(), &entry) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotADirectory => {
                    remove_file_at(child.as_raw_handle(), &entry)?;
                }
                Err(error) => return Err(error),
            }
        }
        remove_directory(parent, name)
    }

    fn remove_file_at(parent: Handle, name: &str) -> std::io::Result<()> {
        let child = open_relative_with_access(
            parent,
            &component(name)?,
            false,
            false,
            false,
            false,
            false,
            false,
            false,
            true,
        )?;
        let mut info = IoStatusBlock {
            status: STATUS_SUCCESS,
            information: 0,
        };
        let mut disposition = FileDispositionInformation { delete_file: 1 };
        let status = unsafe {
            NtSetInformationFile(
                child.as_raw_handle(),
                &mut info,
                (&mut disposition as *mut FileDispositionInformation).cast(),
                size_of::<FileDispositionInformation>() as u32,
                FILE_DISPOSITION_INFORMATION,
            )
        };
        status_result(status, info.status)
    }

    fn read_names_handle(
        handle: Handle,
        max_entries: usize,
        max_name_bytes: usize,
    ) -> std::io::Result<Vec<String>> {
        let mut names = Vec::new();
        let mut restart = 1u8;
        loop {
            let mut buffer = vec![0u8; 64 * 1024];
            let mut info = IoStatusBlock {
                status: STATUS_SUCCESS,
                information: 0,
            };
            let status = unsafe {
                NtQueryDirectoryFile(
                    handle,
                    null_mut(),
                    null_mut(),
                    null_mut(),
                    &mut info,
                    buffer.as_mut_ptr().cast(),
                    buffer.len() as u32,
                    FILE_DIRECTORY_INFORMATION,
                    0,
                    null_mut(),
                    restart,
                )
            };
            restart = 0;
            if status == STATUS_NO_MORE_FILES {
                break;
            }
            if status != STATUS_SUCCESS && status != STATUS_BUFFER_OVERFLOW {
                return Err(io_error(status));
            }
            let returned = info.information.min(buffer.len());
            if returned == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Windows directory query made no progress",
                ));
            }
            let mut records = 0usize;
            let mut offset = 0usize;
            while offset + size_of::<FileDirectoryInformationHeader>() <= returned {
                let header = unsafe {
                    std::ptr::read_unaligned(
                        buffer.as_ptr().add(offset) as *const FileDirectoryInformationHeader
                    )
                };
                let name_len = header.file_name_length as usize;
                let name_start = offset + size_of::<FileDirectoryInformationHeader>();
                if name_len % 2 != 0 || name_start.checked_add(name_len).is_none() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "malformed Windows directory record",
                    ));
                }
                let name_end = name_start + name_len;
                if name_end > returned {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "truncated Windows directory record",
                    ));
                }
                if name_len > max_name_bytes || names.len() >= max_entries {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Windows directory entry bound exceeded",
                    ));
                }
                let words = (0..name_len / 2)
                    .map(|index| unsafe {
                        let bytes = buffer.as_ptr().add(name_start + index * 2);
                        u16::from_le_bytes([*bytes, *bytes.add(1)])
                    })
                    .collect::<Vec<_>>();
                let value = String::from_utf16(&words).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid Windows filename")
                })?;
                records += 1;
                if value != "." && value != ".." {
                    names.push(value);
                }
                if header.next_entry_offset == 0 {
                    break;
                }
                let next = header.next_entry_offset as usize;
                if next < size_of::<FileDirectoryInformationHeader>()
                    || offset.checked_add(next).is_none()
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid Windows directory record offset",
                    ));
                }
                offset += next;
            }
            if records == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Windows directory query returned no complete entry",
                ));
            }
            if status == STATUS_SUCCESS {
                continue;
            }
        }
        Ok(names)
    }

    pub(crate) struct DirectoryCapability {
        handle: OwnedHandle,
    }

    impl DirectoryCapability {
        pub(crate) fn open_path(path: &Path, create: bool) -> std::io::Result<Self> {
            let (root, names) = wide_path(path)?;
            let drive = open_drive_root(&root)
                .map_err(|error| stage_error("drive_root", None, None, error))?;
            let mut parent = drive.as_raw_handle();
            let mut retained = None;
            let mut existing = Vec::new();
            for (index, name) in names.iter().enumerate() {
                let final_component = index + 1 == names.len();
                let next = match open_relative_with_access(
                    parent,
                    name,
                    false,
                    true,
                    false,
                    final_component,
                    create && final_component,
                    false,
                    false,
                    false,
                ) {
                    Ok(next) => next,
                    Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                        let creator = reopen_parent_for_creation(drive.as_raw_handle(), &existing)
                            .map_err(|error| {
                                stage_error("reopen_creator", Some(index), Some(name), error)
                            })?;
                        open_relative_with_access(
                            creator.as_raw_handle(),
                            name,
                            true,
                            true,
                            false,
                            true,
                            true,
                            false,
                            false,
                            false,
                        )
                        .map_err(|error| {
                            stage_error("FILE_OPEN_IF", Some(index), Some(name), error)
                        })?
                    }
                    Err(error) => {
                        return Err(stage_error(
                            "existing_traversal",
                            Some(index),
                            Some(name),
                            error,
                        ))
                    }
                };
                parent = next.as_raw_handle();
                retained = Some(next);
                existing.push(name.clone());
            }
            retained.map(|handle| Self { handle }).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "roster capability requires a non-root directory path",
                )
            })
        }

        pub(crate) fn open_dir(&self, name: &str, create: bool) -> std::io::Result<Self> {
            Ok(Self {
                handle: open_dir_handle(self.handle.as_raw_handle(), name, create)?,
            })
        }

        pub(crate) fn read_names_bounded(
            &self,
            max_entries: usize,
            max_name_bytes: usize,
        ) -> std::io::Result<Vec<String>> {
            read_names_handle(self.handle.as_raw_handle(), max_entries, max_name_bytes)
        }

        pub(crate) fn read_file(&self, name: &str, limit: usize) -> std::io::Result<Vec<u8>> {
            let child = open_relative(
                self.handle.as_raw_handle(),
                &component(name)?,
                false,
                false,
                false,
            )?;
            let file = unsafe { std::fs::File::from_raw_handle(child.into_raw_handle()) };
            let max = limit.saturating_add(1) as u64;
            let mut bytes = Vec::new();
            file.take(max).read_to_end(&mut bytes)?;
            if bytes.len() > limit {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "roster file exceeds configured read bound",
                ));
            }
            Ok(bytes)
        }

        pub(crate) fn write_new(
            &self,
            name: &str,
            bytes: &[u8],
            _mode: u32,
        ) -> std::io::Result<()> {
            let child = open_relative(
                self.handle.as_raw_handle(),
                &component(name)?,
                false,
                false,
                true,
            )?;
            let mut file = unsafe { std::fs::File::from_raw_handle(child.into_raw_handle()) };
            file.write_all(bytes)?;
            file.sync_all()
        }

        pub(crate) fn rename_to(
            &self,
            from: &str,
            destination: &Self,
            to: &str,
        ) -> std::io::Result<()> {
            let source = open_relative_with_access(
                self.handle.as_raw_handle(),
                &component(from)?,
                false,
                false,
                false,
                false,
                false,
                false,
                false,
                true,
            )?;
            let destination_name = component(to)?;
            match open_relative(
                destination.handle.as_raw_handle(),
                &destination_name,
                false,
                false,
                false,
            ) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            // FILE_RENAME_INFORMATION has a variable UTF-16 tail immediately
            // after FileNameLength. `repr(C)` aligns the fixed header to the
            // handle's alignment, so its size includes padding that is not
            // part of the native variable-tail layout.
            let name_offset = std::mem::offset_of!(FileRenameInformationHeader, file_name_length)
                + size_of::<u32>();
            let name_bytes = destination_name
                .len()
                .checked_mul(size_of::<u16>())
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "roster rename name length overflow",
                    )
                })?;
            let total_bytes = name_offset.checked_add(name_bytes).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "roster rename buffer length overflow",
                )
            })?;
            let mut bytes = vec![0u8; total_bytes];
            let header = bytes.as_mut_ptr() as *mut FileRenameInformationHeader;
            unsafe {
                (*header).replace_if_exists = 1;
                (*header).root_directory = destination.handle.as_raw_handle();
                (*header).file_name_length = name_bytes as u32;
                std::ptr::copy_nonoverlapping(
                    destination_name.as_ptr(),
                    bytes.as_mut_ptr().add(name_offset) as *mut u16,
                    destination_name.len(),
                );
            }
            let mut info = IoStatusBlock {
                status: STATUS_SUCCESS,
                information: 0,
            };
            let status = unsafe {
                NtSetInformationFile(
                    source.as_raw_handle(),
                    &mut info,
                    bytes.as_mut_ptr().cast(),
                    bytes.len() as u32,
                    FILE_RENAME_INFORMATION,
                )
            };
            status_result(status, info.status)
        }

        pub(crate) fn remove_file(&self, name: &str) -> std::io::Result<()> {
            remove_file_at(self.handle.as_raw_handle(), name)
        }

        pub(crate) fn quarantine(&self, name: &str) -> std::io::Result<()> {
            let target = format!("{name}.corrupt");
            self.rename_to(name, self, &target)
        }

        pub(crate) fn remove_tree(&self, name: &str) -> std::io::Result<()> {
            remove_tree_at(self.handle.as_raw_handle(), name)
        }

        pub(crate) fn sync(&self) -> std::io::Result<()> {
            // Microsoft documents FlushFileBuffers for file and volume
            // handles, not directory handles. Do not report directory
            // metadata durability that this capability cannot prove.
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Windows directory durability sync is unsupported",
            ))
        }
    }
}

#[cfg(windows)]
pub(crate) use windows_directory::DirectoryCapability;

#[cfg(not(any(unix, windows)))]
pub(crate) struct DirectoryCapability;

#[cfg(not(any(unix, windows)))]
impl DirectoryCapability {
    fn unsupported() -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "handle-relative roster persistence is unavailable on this platform",
        )
    }

    pub(crate) fn open_path(_: &Path, _: bool) -> std::io::Result<Self> {
        Err(Self::unsupported())
    }

    pub(crate) fn open_dir(&self, _: &str, _: bool) -> std::io::Result<Self> {
        Err(Self::unsupported())
    }

    pub(crate) fn read_names_bounded(&self, _: usize, _: usize) -> std::io::Result<Vec<String>> {
        Err(Self::unsupported())
    }

    pub(crate) fn read_file(&self, _: &str, _: usize) -> std::io::Result<Vec<u8>> {
        Err(Self::unsupported())
    }

    pub(crate) fn write_new(&self, _: &str, _: &[u8], _: u32) -> std::io::Result<()> {
        Err(Self::unsupported())
    }

    pub(crate) fn rename_to(&self, _: &str, _: &Self, _: &str) -> std::io::Result<()> {
        Err(Self::unsupported())
    }

    pub(crate) fn remove_file(&self, _: &str) -> std::io::Result<()> {
        Err(Self::unsupported())
    }

    pub(crate) fn quarantine(&self, _: &str) -> std::io::Result<()> {
        Err(Self::unsupported())
    }

    pub(crate) fn remove_tree(&self, _: &str) -> std::io::Result<()> {
        Err(Self::unsupported())
    }

    pub(crate) fn sync(&self) -> std::io::Result<()> {
        Err(Self::unsupported())
    }
}

/// Atomically replace `path` with `bytes`.
///
/// The temp file lives in the same directory (rename must not cross a
/// filesystem) and is created `0600` on Unix so secret-bearing files
/// (identity anchor, custody store) are never readable mid-write —
/// callers that want looser permissions relax them afterwards, as
/// before. `std::fs::rename` replaces the destination on every
/// platform we ship (on Windows it maps to `MOVEFILE_REPLACE_EXISTING`).
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = temp_path(path)?;
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        // Data must be on disk before the rename publishes it, or a
        // power cut can leave the *new* name pointing at unwritten
        // blocks — the exact corruption this module exists to end.
        f.sync_all()?;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    // Best-effort: persist the rename itself. A missed dir-fsync can
    // only resurface the previous complete file, which is safe.
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Move a corrupt state file aside as `{file_name}.corrupt` (replacing
/// any earlier quarantine — the freshest failure is the interesting
/// one) and return where it went. `None` means the rename itself
/// failed and the caller should leave the file alone rather than risk
/// looping on it.
pub(crate) fn quarantine(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?;
    let mut quarantined = name.to_os_string();
    quarantined.push(".corrupt");
    let dest = path.with_file_name(quarantined);
    std::fs::rename(path, &dest).ok()?;
    Some(dest)
}

fn temp_path(path: &Path) -> std::io::Result<PathBuf> {
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("no file name in {}", path.display()),
        )
    })?;
    let mut tmp = name.to_os_string();
    tmp.push(".tmp");
    Ok(path.with_file_name(tmp))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mom-persist-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn write_atomic_replaces_and_leaves_no_temp() {
        let dir = tmpdir("write");
        let path = dir.join("state.json");
        write_atomic(&path, b"first").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        write_atomic(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        assert!(
            !path.with_file_name("state.json.tmp").exists(),
            "temp file must not survive a successful write"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_creates_files_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("mode");
        let path = dir.join("secret.json");
        write_atomic(&path, b"{}").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "fresh state files must be owner-only");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn quarantine_moves_the_file_aside() {
        let dir = tmpdir("quarantine");
        let path = dir.join("roster.json");
        std::fs::write(&path, b"").unwrap();
        let dest = quarantine(&path).expect("quarantine succeeds");
        assert!(!path.exists(), "original must be gone");
        assert_eq!(dest, dir.join("roster.json.corrupt"));
        assert_eq!(std::fs::read(&dest).unwrap(), b"", "bytes preserved");
        // A second corruption replaces the first quarantine.
        std::fs::write(&path, b"worse").unwrap();
        let dest2 = quarantine(&path).expect("re-quarantine succeeds");
        assert_eq!(std::fs::read(&dest2).unwrap(), b"worse");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn selected_root_accepts_ancestor_alias_but_refuses_leaf_and_retains_handle() {
        use std::os::unix::fs::symlink;

        let sandbox = tempfile::tempdir().expect("selection sandbox");
        let base = std::fs::canonicalize(sandbox.path()).expect("test namespace anchor");
        let parent = base.join("physical-parent");
        let alias = base.join("selected-parent");
        let outside = base.join("outside");
        std::fs::create_dir(&parent).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), b"unchanged").unwrap();
        symlink(&parent, &alias).unwrap();
        let selected = alias.join("state");
        assert_eq!(
            DirectoryCapability::open_selected_root(&selected, false)
                .err()
                .unwrap()
                .kind(),
            std::io::ErrorKind::NotFound,
        );
        assert!(!parent.join("state").exists());
        let held = DirectoryCapability::open_selected_root(&selected, true).expect("selected root");
        held.write_new("before", b"original", 0o600).unwrap();
        assert!(
            DirectoryCapability::open_path(&selected, false).is_err(),
            "the original strict walker must still reject the alias"
        );
        assert_eq!(
            std::fs::read(parent.join("state/before")).unwrap(),
            b"original"
        );

        // A symlink at the root leaf is never part of parent selection.
        symlink(&outside, parent.join("linked-root")).unwrap();
        for create in [false, true] {
            assert!(
                DirectoryCapability::open_selected_root(&alias.join("linked-root"), create,)
                    .is_err()
            );
        }

        // Swapping the selected ancestor after acquisition cannot redirect
        // any operation on the already-retained directory.
        std::fs::remove_file(&alias).unwrap();
        symlink(&outside, &alias).unwrap();
        held.write_new("after-parent-swap", b"original", 0o600)
            .unwrap();
        assert!(parent.join("state/after-parent-swap").is_file());
        assert!(!outside.join("state").exists());

        // Nor can replacing the acquired root itself redirect that handle.
        let original = parent.join("state-moved");
        std::fs::rename(parent.join("state"), &original).unwrap();
        symlink(&outside, parent.join("state")).unwrap();
        assert!(DirectoryCapability::open_selected_root(&parent.join("state"), true).is_err());
        held.write_new("after-root-swap", b"original", 0o600)
            .unwrap();
        assert!(original.join("after-root-swap").is_file());
        assert!(!outside.join("after-root-swap").exists());
        assert_eq!(
            std::fs::read(outside.join("sentinel")).unwrap(),
            b"unchanged"
        );
    }

    #[cfg(unix)]
    #[test]
    fn selected_root_missing_suffix_and_traversal_preserve_creation_boundary() {
        use std::os::unix::fs::symlink;

        let sandbox = tempfile::tempdir().expect("selection sandbox");
        let base = std::fs::canonicalize(sandbox.path()).unwrap();
        let selected = base.join("missing-parent/also-missing/state");
        assert_eq!(
            DirectoryCapability::open_selected_root(&selected, false)
                .err()
                .unwrap()
                .kind(),
            std::io::ErrorKind::NotFound,
        );
        assert!(!base.join("missing-parent").exists());
        let held = DirectoryCapability::open_selected_root(&selected, true).unwrap();
        held.write_new("entry", b"owned", 0o600).unwrap();
        assert_eq!(std::fs::read(selected.join("entry")).unwrap(), b"owned");

        for invalid in [
            PathBuf::from("relative-state/missing"),
            base.join("must-not-create/../state"),
        ] {
            assert_eq!(
                DirectoryCapability::open_selected_root(&invalid, true)
                    .err()
                    .unwrap()
                    .kind(),
                std::io::ErrorKind::InvalidInput,
            );
        }
        assert!(!base.join("must-not-create").exists());
        assert_eq!(
            DirectoryCapability::open_selected_root(Path::new("/"), true)
                .err()
                .unwrap()
                .kind(),
            std::io::ErrorKind::InvalidInput,
        );

        // A dangling selected parent alias is an error, not permission to
        // create the absent target as an alternative namespace.
        let absent = base.join("absent-target");
        let dangling = base.join("dangling-parent");
        symlink(&absent, &dangling).unwrap();
        assert!(DirectoryCapability::open_selected_root(&dangling.join("state"), true).is_err());
        assert!(!absent.exists());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn directory_capability_rejects_zero_entry_bound_before_growth() {
        let root = tempfile::tempdir().expect("capability root");
        let capability =
            DirectoryCapability::open_selected_root(root.path(), true).expect("root handle");
        capability
            .write_new("entry.json", b"{}", 0o600)
            .expect("entry");
        assert!(capability.read_names_bounded(0, 128).is_err());
        assert!(root.path().join("entry.json").is_file());
    }

    #[cfg(windows)]
    #[test]
    fn directory_capability_can_create_fresh_nested_roster_path() {
        let root = tempfile::tempdir().expect("capability root");
        let path = root.path().join("mesh").join("rosters");
        let capability =
            DirectoryCapability::open_path(&path, true).expect("create-capable roster handle");
        capability
            .write_new("entry.json", b"{}", 0o600)
            .expect("create roster entry through retained handle");
        capability
            .rename_to("entry.json", &capability, "final.json")
            .expect("rename roster entry through retained handle");
        assert!(!path.join("entry.json").exists());
        assert_eq!(std::fs::read(path.join("final.json")).unwrap(), b"{}");
        let read_only =
            DirectoryCapability::open_path(&path, false).expect("read-only existing directory");
        assert_eq!(read_only.read_file("final.json", 128).unwrap(), b"{}");
        capability
            .remove_file("final.json")
            .expect("delete roster entry through retained handle");
        assert!(!path.join("final.json").exists());
        let sync_error = capability
            .sync()
            .expect_err("directory sync must not claim undocumented durability");
        assert_eq!(sync_error.kind(), std::io::ErrorKind::Unsupported);
    }

    #[cfg(unix)]
    #[test]
    fn directory_capability_rejects_nonregular_read_without_blocking() {
        use std::os::unix::ffi::OsStrExt;

        let root = tempfile::tempdir().expect("capability root");
        let pipe = root.path().join("entry.pipe");
        let pipe_name = std::ffi::CString::new(pipe.as_os_str().as_bytes()).expect("pipe name");
        assert_eq!(unsafe { libc::mkfifo(pipe_name.as_ptr(), 0o600) }, 0);
        let capability =
            DirectoryCapability::open_selected_root(root.path(), false).expect("root handle");
        let result = capability.read_file("entry.pipe", 128);
        assert!(
            result.is_err(),
            "FIFO must be refused before any blocking read"
        );
    }
}
