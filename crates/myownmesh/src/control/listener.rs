//! How the control endpoint comes into existence, and who is allowed to
//! speak to it.
//!
//! This module owns one piece of state: the local socket itself — where it
//! lives, the permissions it and its parent carry, and the identity check
//! applied to each connection. Nothing here knows what the protocol says.
//! Dispatch, framing and the wire schema are the caller's concern, and the
//! only things this module hands back are a bound listener and a verdict on
//! a peer.
//!
//! The two platforms differ in where the check lives rather than in what is
//! checked. Unix proves same-euid peer credentials against an owner-only
//! socket under an owner-only parent; Windows installs a DACL naming the
//! current token's user SID exactly. Both answer the same question.

use std::path::PathBuf;

use anyhow::{Context, Result};
use interprocess::local_socket::{
    tokio::prelude::*, GenericFilePath, GenericNamespaced, ListenerOptions,
};

/// Default control socket name (Unix abstract or Windows named-pipe
/// segment). Overridable via `config.daemon.control_socket`.
#[cfg(not(unix))]
fn default_socket_name() -> String {
    "myownmesh.sock".to_string()
}

/// Resolve the platform-appropriate listener name. On Unix this
/// is `~/.myownmesh/daemon.sock`; on Windows it's a named-pipe
/// segment under the local namespace.
pub(super) fn resolve_socket(custom: Option<PathBuf>) -> Result<SocketTarget> {
    if let Some(path) = custom {
        return Ok(SocketTarget::Path(path));
    }
    #[cfg(unix)]
    {
        let path = myownmesh_core::dirs::data_dir()
            .context("data_dir")?
            .join("daemon.sock");
        Ok(SocketTarget::Path(path))
    }
    #[cfg(not(unix))]
    {
        Ok(SocketTarget::Name(default_socket_name()))
    }
}

#[derive(Debug)]
pub(super) enum SocketTarget {
    Path(PathBuf),
    #[allow(dead_code)]
    Name(String),
}

pub(super) fn bind_listener(target: &SocketTarget) -> Result<LocalSocketListener> {
    use interprocess::local_socket::Name;
    let name: Name = match target {
        SocketTarget::Path(p) => {
            #[cfg(unix)]
            prepare_owner_only_socket_parent(p)?;
            // Remove a stale socket if present so re-binds succeed. Never
            // unlink an arbitrary operator-owned path named like the socket:
            // a configured endpoint is input, and rebinding it must not turn
            // a daemon restart into a file-deletion primitive. Symlinks are
            // rejected by the socket-type check rather than followed.
            #[cfg(unix)]
            {
                remove_stale_socket(p)?;
            }
            p.as_path()
                .to_fs_name::<GenericFilePath>()
                .context("control socket path → fs_name")?
        }
        SocketTarget::Name(n) => n
            .clone()
            .to_ns_name::<GenericNamespaced>()
            .context("control socket name → ns_name")?,
    };
    let options = ListenerOptions::new().name(name);
    // `ListenerOptionsExt::mode` is an `fchmod` on the socket fd performed
    // *before* `bind`, which is exactly what makes it race-free: the socket is
    // never visible under any other mode, not even briefly. interprocess 2.4.2
    // documents support for Linux, FreeBSD 14.3+ and OpenBSD, and converts an
    // `EINVAL` from that `fchmod` into `ErrorKind::Unsupported` — which is what
    // macOS returns for an unbound `AF_UNIX` descriptor. So on macOS this is
    // not a weaker option, it is a failing one: passing it there aborts the
    // bind rather than degrading, and the crate removed its racy fallback in
    // 2.3.0 rather than paper over it.
    #[cfg(all(unix, not(target_os = "macos")))]
    let options = {
        use interprocess::os::unix::local_socket::ListenerOptionsExt;
        options.mode(0o600)
    };
    #[cfg(windows)]
    let options = {
        use interprocess::os::windows::{
            local_socket::ListenerOptionsExt, security_descriptor::SecurityDescriptor,
        };
        // Protected DACL naming the current token's user SID exactly. Owner
        // Rights (`OW`) is not equivalent: an elevated token's default owner
        // may be an administrator group.
        let sddl = current_user_pipe_sddl()?;
        let descriptor = SecurityDescriptor::deserialize(&sddl)
            .context("create current-owner pipe security descriptor")?;
        options.security_descriptor(descriptor)
    };
    let listener = options.create_tokio().context("create_tokio")?;
    // macOS only: set explicitly what the builder is not permitted to set.
    //
    // This does reintroduce a bind-then-chmod interval that the
    // `fchmod`-before-`bind` path does not have. That interval is not reachable
    // by another user, and the parent directory is the whole reason why:
    // `prepare_owner_only_socket_parent` has already proved — forcing it if
    // necessary, and re-reading to confirm — that the socket's parent is owned
    // by this euid and carries no group or other bits. A directory that grants
    // no `x` to others cannot be traversed by them, so a socket inside it
    // cannot be opened during the interval whatever its own mode says at that
    // instant. The window is closed by the containing directory, not by luck.
    //
    // The mode is stated exactly rather than left to the process umask, which
    // is neither read nor modified here or anywhere else in this path, and the
    // result is verified below on the same terms as every other platform.
    #[cfg(target_os = "macos")]
    if let SocketTarget::Path(path) = target {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("set owner-only mode on control socket {}", path.display()))?;
    }
    #[cfg(unix)]
    if let SocketTarget::Path(path) = target {
        verify_owner_only_socket_path(path)?;
    }
    Ok(listener)
}

#[cfg(unix)]
fn remove_stale_socket(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return Ok(());
    };
    anyhow::ensure!(
        metadata.file_type().is_socket(),
        "refusing to replace non-socket control endpoint {}",
        path.display()
    );
    anyhow::ensure!(
        metadata.uid() == unsafe { libc::geteuid() },
        "refusing to remove control socket not owned by the daemon user"
    );
    std::fs::remove_file(path)
        .with_context(|| format!("remove stale control socket {}", path.display()))?;
    Ok(())
}

#[cfg(windows)]
fn current_user_pipe_sddl() -> Result<widestring::U16CString> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, LocalFree, HANDLE},
        Security::{
            Authorization::ConvertSidToStringSidW, GetTokenInformation, TokenUser, TOKEN_QUERY,
            TOKEN_USER,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    let mut token: HANDLE = std::ptr::null_mut();
    anyhow::ensure!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0,
        "open current process token: {}",
        std::io::Error::last_os_error()
    );
    struct Token(HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }
    let token = Token(token);
    let mut needed = 0_u32;
    unsafe {
        GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut needed);
    }
    anyhow::ensure!(needed != 0, "measure current token user SID");
    let word = std::mem::size_of::<usize>();
    let mut buffer = vec![0_usize; (needed as usize).div_ceil(word)];
    anyhow::ensure!(
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } != 0,
        "read current token user SID: {}",
        std::io::Error::last_os_error()
    );
    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut sid_text = std::ptr::null_mut();
    anyhow::ensure!(
        unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid_text) } != 0,
        "format current token user SID: {}",
        std::io::Error::last_os_error()
    );
    struct LocalString(windows_sys::core::PWSTR);
    impl Drop for LocalString {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0.cast()) };
        }
    }
    let sid_text = LocalString(sid_text);
    let sid = unsafe { widestring::U16CStr::from_ptr_str(sid_text.0) }.to_string_lossy();
    widestring::U16CString::from_str(format!("D:P(A;;GA;;;{sid})"))
        .context("encode current-user pipe DACL")
}

#[cfg(unix)]
fn prepare_owner_only_socket_parent(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let parent = path
        .parent()
        .context("control socket has no parent directory")?;
    if !parent.exists() {
        let mut builder = std::fs::DirBuilder::new();
        builder
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .with_context(|| format!("create owner-only control directory {}", parent.display()))?;
    }
    let metadata = std::fs::symlink_metadata(parent)?;
    anyhow::ensure!(
        metadata.file_type().is_dir(),
        "control socket parent is not a directory"
    );
    anyhow::ensure!(
        metadata.uid() == unsafe { libc::geteuid() },
        "control socket parent is not owned by the daemon user"
    );
    if metadata.permissions().mode() & 0o077 != 0 {
        // Reaching here proves the directory already existed. A directory this
        // function creates is made with mode 0o700, and `mkdir` applies
        // `mode & !umask` — a umask can only clear bits, never set them — so a
        // directory we just created cannot carry a group or other bit. The
        // branch is therefore only ever entered for a directory that was
        // already on disk before this call.
        //
        // Which makes the chmod below a change to an unrelated pre-existing
        // directory. Hardening our own endpoint is not licence to remove
        // access from a directory the process owner may share deliberately;
        // doing that silently is a destructive side effect, not a security
        // measure. So it is permitted only for the one directory dedicated to
        // MyOwnMesh by construction, and refused with an actionable message
        // everywhere else.
        let dedicated = myownmesh_core::dirs::data_dir()
            .map(|data_dir| parent == data_dir)
            .unwrap_or(false);
        anyhow::ensure!(
            dedicated,
            "control socket parent {} is accessible to other users, and \
             MyOwnMesh will not change an unrelated pre-existing directory; \
             make it owner-only yourself, choose a path whose parent does not \
             yet exist, or use the default control socket",
            parent.display()
        );
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("make control directory owner-only: {}", parent.display()))?;
    }
    let metadata = std::fs::symlink_metadata(parent)?;
    anyhow::ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "control socket parent must be owner-only"
    );
    Ok(())
}

#[cfg(unix)]
fn verify_owner_only_socket_path(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect control socket {}", path.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_socket(),
        "control endpoint is not a socket"
    );
    anyhow::ensure!(
        metadata.uid() == unsafe { libc::geteuid() },
        "control socket is not owned by the daemon user"
    );
    anyhow::ensure!(
        metadata.mode() & 0o777 == 0o600,
        "control socket must have exact owner-only mode 0600"
    );
    Ok(())
}

#[cfg(unix)]
pub(super) fn verify_local_peer(stream: &LocalSocketStream) -> Result<()> {
    let credentials = stream
        .peer_creds()
        .context("read control peer credentials")?;
    let peer = credentials
        .euid()
        .context("control transport did not provide peer euid")?;
    anyhow::ensure!(
        peer == unsafe { libc::geteuid() },
        "control peer is not the daemon user"
    );
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn verify_local_peer(_stream: &LocalSocketStream) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `bind_listener` ends in `create_tokio`, which registers the listener's
    /// descriptor with the Tokio reactor as it is constructed. A plain `#[test]`
    /// has no runtime, so that construction panics with "there is no reactor
    /// running" before any assertion is reached. The runtime is also what makes
    /// the trailing `drop` well-defined, since it is a Tokio resource too.
    ///
    /// **The socket goes in a child directory that does not yet exist**, which
    /// is the branch `prepare_owner_only_socket_parent` creates at mode 0700.
    /// Binding straight into `tempfile::tempdir()` made this control depend on
    /// whatever mode the host's temporary directory happens to carry: on hosted
    /// Linux and macOS runners that directory is accessible to group or other,
    /// so production refused it — correctly — as an unrelated pre-existing
    /// directory it will not silently chmod, and the control failed for its
    /// fixture's arrangement rather than for its subject. "A path whose parent
    /// does not yet exist" is one of the three remedies that refusal names, and
    /// it is the one this control wants: the directory under test is then the
    /// one the daemon itself made, on any host.
    ///
    /// That also makes this the only control over the *create* half of the
    /// rule. `unix_control_refuses_an_accessible_unrelated_parent_without_chmod`
    /// below covers the refuse half.
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_control_endpoint_is_verified_as_exact_owner_only_socket() {
        use interprocess::local_socket::{tokio::prelude::*, GenericFilePath};
        use std::os::unix::fs::{FileTypeExt, MetadataExt};

        let directory = tempfile::tempdir().expect("temporary control root");
        let parent = directory.path().join("private");
        let path = parent.join("control.sock");
        assert!(
            !parent.exists(),
            "non-vacuity: the parent must be absent, so the directory asserted \
             on below is one the daemon created rather than one the host handed us"
        );

        let listener = bind_listener(&SocketTarget::Path(path.clone())).expect("bind control");

        // Exactly 0700 rather than the production predicate `mode & 0o077 == 0`:
        // `mkdir` applies `mode & !umask` and a umask can only clear bits, so a
        // directory created at 0700 keeps its owner bits under every ordinary
        // umask. Asserting the exact value is what makes a regression to 0755
        // fail here instead of passing a weaker "no group or other bit" check.
        let parent_metadata = std::fs::symlink_metadata(&parent).expect("created parent metadata");
        assert!(parent_metadata.file_type().is_dir());
        assert_eq!(parent_metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(parent_metadata.mode() & 0o777, 0o700);

        let metadata = std::fs::symlink_metadata(&path).expect("socket metadata");
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.mode() & 0o777, 0o600);

        // Exercise the real same-euid path, not only the pathname metadata:
        // the client connects after bind, the listener accepts it, and the
        // accepted stream's kernel credentials pass the production verifier.
        let name = path
            .as_path()
            .to_fs_name::<GenericFilePath>()
            .expect("the control socket path is a valid fs name");
        let client = LocalSocketStream::connect(name)
            .await
            .expect("same-euid client connects");
        let server = listener.accept().await.expect("listener accepts client");
        verify_local_peer(&server).expect("accepted peer has the daemon euid");
        drop(server);
        drop(client);
        drop(listener);
    }

    /// A portable raw Unix socket fixture is replaced, but the replacement
    /// still receives the exact owner-only mode and ownership checks. This does
    /// not depend on the production listener's platform-specific Drop, which
    /// may unlink its path on macOS.
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_control_replaces_an_owned_stale_socket() {
        use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

        let directory = tempfile::tempdir().expect("temporary control root");
        let parent = directory.path().join("private");
        std::fs::create_dir(&parent).expect("create private parent");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
            .expect("make private parent owner-only");
        let path = parent.join("control.sock");
        let stale_fixture = std::os::unix::net::UnixListener::bind(&path)
            .expect("portable raw Unix stale socket fixture");
        let stale = std::fs::symlink_metadata(&path).expect("stale socket remains named");
        assert!(stale.file_type().is_socket());
        assert_eq!(stale.uid(), unsafe { libc::geteuid() });
        drop(stale_fixture);

        let replacement = bind_listener(&SocketTarget::Path(path.clone()))
            .expect("owned stale socket is replaced");
        let current = std::fs::symlink_metadata(&path).expect("replacement metadata");
        assert!(current.file_type().is_socket());
        assert_eq!(current.uid(), unsafe { libc::geteuid() });
        assert_eq!(current.mode() & 0o777, 0o600);
        drop(replacement);
    }

    /// A configured endpoint that is a regular file is never removed or
    /// replaced as part of listener setup.
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_control_refuses_non_socket_without_mutation() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let directory = tempfile::tempdir().expect("temporary control root");
        let parent = directory.path().join("private");
        std::fs::create_dir(&parent).expect("create private parent");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
            .expect("make private parent owner-only");
        let path = parent.join("control.sock");
        std::fs::write(&path, b"operator data").expect("create non-socket endpoint");
        let before = std::fs::read(&path).expect("read non-socket endpoint");
        let before_metadata = std::fs::symlink_metadata(&path).expect("stat non-socket endpoint");

        let Err(_) = bind_listener(&SocketTarget::Path(path.clone())) else {
            panic!("a regular file must be refused");
        };
        assert_eq!(std::fs::read(&path).expect("endpoint remains"), before);
        let after_metadata = std::fs::symlink_metadata(&path).expect("stat endpoint remains");
        assert!(after_metadata.file_type().is_file());
        assert_eq!(after_metadata.ino(), before_metadata.ino());
        assert_eq!(
            after_metadata.mode() & 0o777,
            before_metadata.mode() & 0o777
        );
    }

    /// A symlink at the configured endpoint is refused via lstat-style
    /// metadata, never followed and never unlinked.
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_control_refuses_symlink_without_mutation() {
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

        let directory = tempfile::tempdir().expect("temporary control root");
        let parent = directory.path().join("private");
        std::fs::create_dir(&parent).expect("create private parent");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
            .expect("make private parent owner-only");
        let target = parent.join("target");
        let path = parent.join("control.sock");
        std::fs::write(&target, b"target data").expect("create symlink target");
        symlink(&target, &path).expect("create symlink endpoint");
        let before_link = std::fs::symlink_metadata(&path).expect("stat symlink endpoint");

        let Err(_) = bind_listener(&SocketTarget::Path(path.clone())) else {
            panic!("a symlink endpoint must be refused");
        };
        let after_link = std::fs::symlink_metadata(&path).expect("symlink remains");
        assert!(after_link.file_type().is_symlink());
        assert_eq!(after_link.ino(), before_link.ino());
        assert_eq!(
            std::fs::read_link(&path).expect("symlink target remains"),
            target
        );
        assert_eq!(
            std::fs::read(&target).expect("target remains"),
            b"target data"
        );
    }

    /// A custom socket path does not authorize the daemon to chmod the
    /// operator's existing parent directory. Refusal must leave both the
    /// directory and the not-yet-bound socket path untouched.
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_control_refuses_an_accessible_unrelated_parent_without_chmod() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("temporary control root");
        let parent = directory.path().join("shared");
        std::fs::create_dir(&parent).expect("create pre-existing parent");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755))
            .expect("make the parent deliberately shared");
        let path = parent.join("control.sock");

        let Err(error) = bind_listener(&SocketTarget::Path(path.clone())) else {
            panic!("an unrelated shared parent must be refused");
        };
        assert!(error
            .to_string()
            .contains("will not change an unrelated pre-existing directory"));
        assert_eq!(
            std::fs::symlink_metadata(&parent)
                .expect("parent metadata after refusal")
                .permissions()
                .mode()
                & 0o777,
            0o755,
            "refusal does not mutate the operator's directory"
        );
        assert!(
            !path.exists(),
            "the socket is not bound after parent validation refuses"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_pipe_dacl_names_current_token_user_not_owner_rights() {
        let sddl = current_user_pipe_sddl()
            .expect("current user DACL")
            .to_string_lossy();
        assert!(sddl.starts_with("D:P(A;;GA;;;S-1-"));
        assert!(!sddl.contains(";;;WD)"));
        assert!(!sddl.contains(";;;AU)"));
        assert!(!sddl.contains(";;;OW)"));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_current_user_pipe_connects_and_is_accepted() {
        use interprocess::local_socket::{tokio::prelude::*, GenericNamespaced};

        let raw_name = format!(
            "myownmesh-acl-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        );
        let listener = bind_listener(&SocketTarget::Name(raw_name.clone())).expect("bind pipe");
        let name = raw_name
            .to_ns_name::<GenericNamespaced>()
            .expect("pipe name is namespaced");
        let client = LocalSocketStream::connect(name)
            .await
            .expect("same-user client connects");
        let server = listener.accept().await.expect("pipe accepts client");
        verify_local_peer(&server).expect("current-user pipe peer is accepted");
        drop(server);
        drop(client);
        drop(listener);
    }
}
