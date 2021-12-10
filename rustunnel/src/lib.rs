//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

//! `rustunnel` is a sandboxed TLS tunnel library.
//!
//! This library can either [accept](ServerChild) or [initiate](ClientChild) a TLS connection inside a process sandbox.
//! A process utilizing this library should be minimal, limited in scope, and single-threaded, so as to not open any
//! unforeseen security holes or cause sandbox violations.
//!
//! # Portability
//!
//! Currently only Linux is supported, using `libseccomp2` for process sandboxing.
//!
//! # Usage
//!
//! Care should be taken in the sandboxed process to clear all secrets in memory before starting the sandboxed TLS
//! connection, e.g. loaded TLS private keys. The [`clear_on_drop`](clear_on_drop) crate can be used to clear secrets automatically.
//! [`Identity::from_pkcs12_file`] provides an implementation of loading a TLS private key while clearing all secrets in
//! memory.
//!
//! The `log` implementation used in the sandboxed process should take care not to perform any system calls while
//! writing log message which may be disallowed by the process sandbox. Calculating timestamps, for example, may use a
//! prohibited system call. [`logger::Logger`] provides a conforming implementation (without timestamps) which writes to
//! the standard error.
//!
//! It is recommended that [`sandbox::close_all_fds`] be called, as immediately as possible, before running the
//! sandboxed TLS connection, to ensure no additional file descriptors are unintentionally opened in the interim.
//!
//! ```no_run
//! use rustunnel::{tls, ServerChild};
//! use std::net::TcpListener;
//! use std::os::unix::io::AsRawFd as _;
//! use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let (source_tcp_stream, _) = TcpListener::bind("127.0.0.1:8080")?.accept()?;
//! let identity = tls::Identity::from_pkcs12_file(Path::new("/path/to/identity.p12"), "pkcs12 password")?;
//! let target_pipe_stream = rustunnel::stream::ProxyPipeStream::stdio()?;
//!
//! let source_fd = source_tcp_stream.as_raw_fd();
//! let allow_fds = [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO, source_fd];
//! rustunnel::sandbox::close_all_fds(&allow_fds.iter().cloned().collect());
//!
//! let child = ServerChild::new(tls::CaCertificate::System, identity, source_tcp_stream, target_pipe_stream)?;
//! child.run()?;
//! # Ok(())
//! # }
//! ```

#![warn(missing_docs)]

mod alloc;
pub mod logger;
mod proxy;
pub mod sandbox;
#[cfg(target_os = "linux")]
mod seccomp;
pub mod stream;
pub mod tls;
#[doc(hidden)]
pub mod util;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::prelude::*;

use failure::ResultExt;
use log::{debug, error, warn};
use nix::poll::*;

use self::proxy::*;
use self::stream::*;
use self::tls::*;

/// A sandboxed TLS acceptor.
///
/// When [`ServerChild::run`] is executed, a process sandbox will be set up, a TLS connection will be accepted over the
/// given [`TcpStream`], and connection plaintext will be proxied to and from the given [`ProxyPipeStream`].
pub struct ServerChild {
    tls_acceptor:       TlsAcceptor,
    source_tcp_stream:  ProxyTcpStream,
    target_pipe_stream: ProxyPipeStream,
}

/// A sandboxed TLS initiator.
///
/// When [`ClientChild::run`] is executed, a process sandbox will be set up, a TLS connection will be initiated over the
/// given [`TcpStream`], and connection plaintext will be proxied to and from the given [`ProxyPipeStream`].
pub struct ClientChild {
    tls_connector:      TlsConnector,
    source_pipe_stream: ProxyPipeStream,
    target_tcp_stream:  ProxyTcpStream,
}

//
// ServerChild impls
//

impl ServerChild {
    /// Constructs a new `ServerChild`.
    ///
    /// The `tls_ca_cert` specifies the CA certificates to trust when authenticating the accepted client. The
    /// `tls_identity` provides both the certificate chain for the client to authenticate this server and the private
    /// key to use for the TLS connection. The TLS connection will take place over the `source_tcp_stream` and its
    /// plaintext proxied to and from `target_pipe_stream`.
    ///
    /// # Errors
    ///
    /// If there were errors configuring `source_tcp_stream`, or if `tls_ca_cert` or `tls_identity` are invalid, then an
    /// error is returned.
    pub fn new(
        tls_ca_cert: CaCertificate,
        tls_identity: Identity,
        source_tcp_stream: TcpStream,
        target_pipe_stream: ProxyPipeStream,
    ) -> Result<Self, failure::Error>
    {
        let source_tcp_stream = ProxyTcpStream::from_std(source_tcp_stream).context("error setting up tcp stream")?;
        let tls_acceptor = TlsAcceptor::new(tls_identity, tls_ca_cert).context("error setting up tls acceptor")?;

        Ok(ServerChild {
            tls_acceptor,
            source_tcp_stream,
            target_pipe_stream,
        })
    }

    /// Accepts a TLS connection in a process sandbox.
    ///
    /// The process sandbox will be set up when this function is called, and will remain in place after this function
    /// returns.
    ///
    /// # Errors
    ///
    /// If an error occurred setting up the process sandbox, or any error occurs on the TLS connection, then an error is
    /// returned.
    pub fn run(mut self) -> Result<(), failure::Error> {
        setup_sandbox().context("error setting up sandbox")?;

        match handshake(self.tls_acceptor.accept(self.source_tcp_stream)) {
            Ok(mut source_tls_stream) => {
                let _ignore = proxy(
                    "local target",
                    &mut self.target_pipe_stream,
                    "remote source",
                    &mut source_tls_stream,
                );
                Ok(())
            }
            Err(()) => Ok(()),
        }
    }
}

//
// ClientChild impls
//

impl ClientChild {
    /// Constructs a new `ClientChild`.
    ///
    /// The `tls_ca_certs` and `tls_hostname` specify the CA certificates and hostname to trust when authenticating the
    /// server. The optional `tls_identity` provides both the certificate for the server to authenticate this client and
    /// the private key to use for the TLS connection. The TLS connection will take place over the `target_tcp_stream`
    /// and its plaintext proxied to and from `source_pipe_stream`.
    ///
    /// # Errors
    ///
    /// If there were errors configuring `target_tcp_stream`, or if `tls_ca_cert` or `tls_identity` are invalid, then an
    /// error is returned.
    pub fn new(
        tls_hostname: TlsHostname,
        tls_ca_certs: Vec<CaCertificate>,
        tls_identity: Option<Identity>,
        source_pipe_stream: ProxyPipeStream,
        target_tcp_stream: TcpStream,
    ) -> Result<Self, failure::Error>
    {
        let target_tcp_stream = ProxyTcpStream::from_std(target_tcp_stream).context("error setting up tcp stream")?;
        let tls_connector = TlsConnector::new(tls_identity, tls_hostname, tls_ca_certs).context("error setting up tls connector")?;
        Ok(Self {
            tls_connector,
            source_pipe_stream,
            target_tcp_stream,
        })
    }

    /// Initiates a TLS connection in a process sandbox.
    ///
    /// The process sandbox will be set up when this function is called, and will remain in place after this function
    /// returns.
    ///
    /// # Errors
    ///
    /// If an error occurred setting up the process sandbox, or any error occurs on the TLS connection, then an error is
    /// returned.
    pub fn run(mut self) -> Result<(), failure::Error> {
        setup_sandbox().context("error setting up sandbox")?;

        debug!("starting TLS handshake");
        match handshake(self.tls_connector.connect(self.target_tcp_stream)) {
            Ok(mut target_tls_stream) => {
                debug!("finished TLS handshake");
                let _ignore = proxy(
                    "local source",
                    &mut self.source_pipe_stream,
                    "remote target",
                    &mut target_tls_stream,
                );
                Ok(())
            }
            Err(()) => Ok(()),
        }
    }
}

//
// internal
//

fn handshake<T: AsRawFd + Read + Write>(mut accept_result: Result<TlsStream<T>, HandshakeError<T>>) -> Result<TlsStream<T>, ()> {
    loop {
        let (stream, poll_flags) = match accept_result {
            Ok(tls_stream) => return Ok(tls_stream),
            Err(HandshakeError::WantRead(stream)) => (stream, PollFlags::POLLIN),
            Err(HandshakeError::WantWrite(stream)) => (stream, PollFlags::POLLOUT),
            Err(HandshakeError::Failure(error)) => {
                warn!("handshake error: {}", error);
                return Err(());
            }
        };
        let mut poll_fds = [PollFd::new(stream.as_raw_fd(), poll_flags)];

        // XXX handshake timeout
        match poll(&mut poll_fds, -1) {
            Ok(_event_count) => (),
            Err(nix::Error::EINTR) => (),
            Err(error) => {
                error!("error polling sockets: {}", error);
                return Err(());
            }
        }
        accept_result = stream.handshake();
    }
}

fn proxy(
    stream_0_name: &'static str,
    stream_0: &mut ProxyPipeStream,
    stream_1_name: &'static str,
    stream_1: &mut (impl ProxyRead + ProxyWrite + AsRawFd),
) -> Result<(), ()>
{
    let mut buffer_0 = ProxyBuffer::new();
    let mut buffer_1 = ProxyBuffer::new();

    loop {
        let mut stream_0_flags = PollFlags::empty();
        let mut stream_1_flags = PollFlags::empty();

        let buffer_0_flags = buffer_0.proxy(stream_0_name, stream_0, stream_1_name, stream_1)?;
        stream_0_flags |= buffer_0_flags.0;
        stream_1_flags |= buffer_0_flags.1;

        let buffer_1_flags = buffer_1.proxy(stream_1_name, stream_1, stream_0_name, stream_0)?;
        stream_0_flags |= buffer_1_flags.1;
        stream_1_flags |= buffer_1_flags.0;

        if buffer_0.is_closed() && buffer_1.is_closed() {
            break;
        }

        let stream_0_write_fd = stream_0.write_fd().unwrap_or(-1);

        fn new_poll_fd(mut fd: RawFd, flags: PollFlags) -> PollFd {
            if flags.is_empty() {
                fd = -1;
            }
            PollFd::new(fd, flags)
        }
        let mut poll_fds = [
            new_poll_fd(stream_0.read_fd(), stream_0_flags & PollFlags::POLLIN),
            new_poll_fd(stream_0_write_fd, stream_0_flags & PollFlags::POLLOUT),
            new_poll_fd(stream_1.as_raw_fd(), stream_1_flags),
        ];

        debug!("polling: {:?}", &poll_fds);
        match poll(&mut poll_fds, -1) {
            Ok(_event_count) => (),
            Err(nix::Error::EINTR) => continue,
            Err(error) => {
                error!("error polling sockets: {}", error);
                return Err(());
            }
        }
    }
    Ok(())
}

fn setup_sandbox() -> Result<(), failure::Error> {
    #[cfg(target_os = "linux")] {
        let () = setup_seccomp().context("error setting up seccomp")?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))] {
        // pretend we're setting up a sandbox to inhibit "unused code" lints
        if false {
            sandbox::init_malloc();
            sandbox::configure_panic_hook();
        }
        unimplemented!("sandboxing not implemented for this target")
    }
}

#[cfg(target_os = "linux")]
fn setup_seccomp() -> Result<(), failure::Error> {
    use nix::errno::Errno;
    use self::seccomp::*;

    macro_rules! cstr {
        ($str:literal) => {
            std::ffi::CStr::from_bytes_with_nul(concat!($str, "\0").as_bytes()).expect("cstr macro bug")
        };
    }

    configure_openssl_for_seccomp()?;

    let mut seccomp = SeccompContext::new().map_err(|()| failure::format_err!("error creating seccomp context"))?;

    let () = seccomp.allow(cstr!("poll"))?;
    let () = seccomp.allow(cstr!("read"))?;
    let () = seccomp.allow(cstr!("write"))?;
    let () = seccomp.allow(cstr!("shutdown"))?;
    let () = seccomp.allow(cstr!("close"))?;
    let () = seccomp.allow(cstr!("exit"))?;
    let () = seccomp.allow(cstr!("exit_group"))?;
    let () = seccomp.allow(cstr!("sigreturn"))?;
    let () = seccomp.allow(cstr!("munmap"))?;
    let () = seccomp.allow(cstr!("mremap"))?;
    let () = seccomp.allow(cstr!("brk"))?;
    let () = seccomp.allow(cstr!("futex"))?;
    let () = seccomp.allow(cstr!("restart_syscall"))?;
    let () = seccomp.allow(cstr!("sched_yield"))?;
    let () = seccomp.allow(cstr!("pause"))?;
    let () = seccomp.allow(cstr!("getpid"))?;
    // XXX allow sigaction/sigprocmask/sigtimedwait/sigaltstack?
    // XXX allow restricted prctl? (used in glibc)

    let () = seccomp.deny_errno(cstr!("openat"), Errno::ENOSYS)?;
    let () = seccomp.deny_errno(cstr!("sigaltstack"), Errno::ENOSYS)?;

    sandbox::init_malloc();
    sandbox::configure_panic_hook();
    let () = seccomp.load()?;
    Ok(())
}
