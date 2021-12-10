//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

//! Streams for use with sandboxed TLS connections.

use std::io;
use std::io::prelude::*;
use std::net::TcpStream;
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};

use nix::unistd;

use crate::util;

/// A [`Read`]/[`Write`] stream used for the plaintext end of a `rustunnel` TLS tunnel.
///
/// This struct holds the file descriptors used for reading and writing the plaintext end of a `rustunnel` TLS tunnel.
/// Although any [`RawFd`] may be passed into [`ProxyPipeStream::new`], only those corresponding to [pipes] are
/// guaranteed to behave correctly. In the most common case, [`ProxyPipeStream::stdio`] can be used to communicate over
/// the standard input and output pipes.
///
/// [pipes]: nix::unistd::pipe
pub struct ProxyPipeStream {
    read_fd:  RawFd,
    write_fd: Option<RawFd>,
}

pub(crate) struct ProxyTcpStream {
    fd: RawFd,
}

pub(crate) trait ProxyRead {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, ProxyStreamError>;
}
pub(crate) trait ProxyWrite {
    fn write(&mut self, buf: &[u8]) -> Result<usize, ProxyStreamError>;
    fn shutdown(&mut self) -> Result<(), ProxyStreamError>;
}

#[derive(Debug)]
pub(crate) enum ProxyStreamError {
    WantRead,
    WantWrite,
    Io(io::Error),
}

//
// ProxyTcpStream impls
//

impl ProxyTcpStream {
    pub fn from_std(stream: TcpStream) -> io::Result<Self> {
        stream.set_nodelay(true)?;
        stream.set_nonblocking(true)?;
        Ok(Self { fd: stream.into_raw_fd() })
    }
}

impl Read for ProxyTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        <&Self>::read(&mut &*self, buf)
    }
}
impl Write for ProxyTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        <&Self>::write(&mut &*self, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        <&Self>::flush(&mut &*self)
    }
}

impl Read for &'_ ProxyTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        util::convert_nix(unistd::read(self.fd, buf))
    }
}

impl Write for &'_ ProxyTcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        util::convert_nix(unistd::write(self.fd, buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsRawFd for ProxyTcpStream {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for ProxyTcpStream {
    fn drop(&mut self) {
        let _ignore = unistd::close(self.fd);
    }
}

//
// ProxyPipeStream
//

impl ProxyPipeStream {
    /// Constructs a new [`ProxyPipeStream`] from two [`RawFd`]s for reading and writing.
    ///
    /// The file descriptors `read_fd` and `write_fd` form the reading and writing halves of the [`ProxyPipeStream`],
    /// respectively. Both file descriptors must be capable of enabling the [`O_NONBLOCK`] flag. Only [pipe] based file
    /// descriptors are supported.
    ///
    /// # Errors
    ///
    /// If any error occurred configuring the `read_fd` or `write_fd`, then an error is returned.
    ///
    /// [`O_NONBLOCK`]: nix::fcntl::OFlag::O_NONBLOCK
    /// [pipe]: nix::unistd::pipe
    pub fn new(read_fd: RawFd, write_fd: RawFd) -> io::Result<Self> {
        util::set_nonblocking(read_fd)?;
        util::set_nonblocking(write_fd)?;
        Ok(Self {
            read_fd,
            write_fd: Some(write_fd),
        })
    }

    /// Constructs a new [`ProxyPipeStream`] from the standard input and output for reading and writing.
    ///
    /// This function currently permanently locks [`Stdin`] and [`Stdout`].
    ///
    /// [`Stdin`]: std::io::Stdin
    /// [`Stdout`]: std::io::Stdout
    ///
    /// # Errors
    ///
    /// If any error occurred configuring the standard input or output, then an error is returned.
    pub fn stdio() -> io::Result<Self> {
        let stdin = Box::leak(Box::new(io::stdin()));
        let _stdin_lock = Box::leak(Box::new(stdin.lock()));
        let stdout = Box::leak(Box::new(io::stdout()));
        let _stdout_lock = Box::leak(Box::new(stdout.lock()));

        Self::new(libc::STDIN_FILENO, libc::STDOUT_FILENO)
    }

    pub(crate) fn read_fd(&self) -> RawFd {
        self.read_fd
    }

    pub(crate) fn write_fd(&self) -> Option<RawFd> {
        self.write_fd
    }
}

impl Read for ProxyPipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        <&Self>::read(&mut &*self, buf)
    }
}
impl Write for ProxyPipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        <&Self>::write(&mut &*self, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        <&Self>::flush(&mut &*self)
    }
}

impl Read for &'_ ProxyPipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        util::convert_nix(unistd::read(self.read_fd, buf))
    }
}

impl Write for &'_ ProxyPipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.write_fd {
            Some(write_fd) => util::convert_nix(unistd::write(write_fd, buf)),
            None => Err(io::ErrorKind::NotConnected.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ProxyRead for ProxyPipeStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, ProxyStreamError> {
        <&Self as Read>::read(&mut &*self, buf).map_err(|error: io::Error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                ProxyStreamError::WantRead
            } else {
                ProxyStreamError::Io(error)
            }
        })
    }
}

impl ProxyWrite for ProxyPipeStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize, ProxyStreamError> {
        <&Self as Write>::write(&mut &*self, buf).map_err(|error: io::Error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                ProxyStreamError::WantWrite
            } else {
                ProxyStreamError::Io(error)
            }
        })
    }

    fn shutdown(&mut self) -> Result<(), ProxyStreamError> {
        if let Some(write_fd) = self.write_fd.take() {
            util::convert_nix(unistd::close(write_fd)).map_err(ProxyStreamError::Io)
        } else {
            Ok(())
        }
    }
}

impl Drop for ProxyPipeStream {
    fn drop(&mut self) {
        if let Some(write_fd) = self.write_fd {
            let _ignore = unistd::close(write_fd);
        }
        let _ignore = unistd::close(self.read_fd);
    }
}
