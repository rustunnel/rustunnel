//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::io;
use std::os::unix::prelude::*;

use nix::fcntl;
use nix::fcntl::OFlag;

pub fn convert_nix<T>(result: nix::Result<T>) -> io::Result<T> {
    result.map_err(|error| error.into())
}

pub fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = OFlag::from_bits(convert_nix(fcntl::fcntl(fd, fcntl::F_GETFL))?).unwrap_or_else(OFlag::empty);
    assert_eq!(convert_nix(fcntl::fcntl(fd, fcntl::F_SETFL(flags | OFlag::O_NONBLOCK)))?, 0);
    Ok(())
}
