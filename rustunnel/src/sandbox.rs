//! Process sandbox utilities.

use std::collections::BTreeSet;
use std::os::unix::prelude::*;
use std::fs;
use std::path::Path;
use std::panic;

use failure::{format_err, ResultExt};
use nix::errno::Errno;
use nix::unistd;

use crate::util;

/// Closes all file descriptors except for those in `keep_fds`.
///
/// A sandboxed process is allowed to read and write to open file descriptors, but not to open new file descriptors.
/// Therefore, the sandbox will be effective only if the sandboxed process has only harmless file descriptors open
/// (stdin, stdout, and stderr, for example). This function is especially useful after a process [`fork()`] (like when
/// being spawned by [`Command::new`], for example) since any file descriptors open in the parent process may still be
/// open in the child.
///
/// # Portability
///
/// Currently this function only supports Linux with a mounted `/proc`, and fails otherwise.
///
/// # Errors
///
/// If any error occurred closing any file descriptors, then an error is returned.
///
/// [`fork()`]: nix::unistd::fork
/// [`Command::new`]: std::process::Command::new
pub fn close_all_fds(keep_fds: &BTreeSet<RawFd>) -> Result<(), failure::Error> {
    let fd_dir = fs::read_dir(Path::new(r"/proc/self/fd/")).context("error reading /proc/self/fd/")?;
    let mut fds = BTreeSet::new();
    for dir_entry_result in fd_dir {
        let fd_name = dir_entry_result.context("error reading /proc/self/fd/")?.file_name();
        let fd = fd_name
            .to_string_lossy()
            .parse::<RawFd>()
            .with_context(|_| format_err!("invalid fd number in /proc/self/fd/: {:?}", fd_name))?;
        fds.insert(fd);
    }
    for fd in fds.difference(&keep_fds) {
        match unistd::close(*fd) {
            Ok(()) => (),
            Err(nix::Error::Sys(Errno::EBADF)) => (),
            Err(error) => util::convert_nix(Err(error))?,
        }
    }
    Ok(())
}

pub(crate) fn init_malloc() {
    // ensure dlmalloc is initialized
    drop(Box::new(1));
}

pub(crate) fn configure_panic_hook() {
    let default_panic_hook = panic::take_hook();

    panic::set_hook(Box::new(move |panic_info: &panic::PanicInfo<'_>| {
        default_panic_hook(panic_info);
        // trigger abort via double panic
        panic!("aborting")
    }));
}
