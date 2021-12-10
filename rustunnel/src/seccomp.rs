//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::ffi::CStr;
use std::ptr::NonNull;

use nix::errno::Errno;
use seccomp_sys::*;

pub struct SeccompContext {
    context: NonNull<scmp_filter_ctx>,
}

//
// SeccompContext impls
//

impl SeccompContext {
    pub fn new() -> Result<Self, ()> {
        let context = NonNull::new(unsafe { seccomp_init(SCMP_ACT_KILL_PROCESS) }).ok_or(())?;
        Ok(Self { context })
    }

    pub fn allow(&mut self, syscall_name: &CStr) -> Result<(), Errno> {
        let syscall_nr = unsafe { seccomp_syscall_resolve_name(syscall_name.as_ptr()) };
        assert_eq!(
            0,
            errno_result(unsafe { seccomp_rule_add(self.context.as_ptr(), SCMP_ACT_ALLOW, syscall_nr, 0) })?
        );
        Ok(())
    }

    pub fn deny_errno(&mut self, syscall_name: &CStr, errno: Errno) -> Result<(), Errno> {
        let syscall_nr = unsafe { seccomp_syscall_resolve_name(syscall_name.as_ptr()) };
        assert_eq!(
            0,
            errno_result(unsafe { seccomp_rule_add(self.context.as_ptr(), SCMP_ACT_ERRNO(errno as u32), syscall_nr, 0) })?
        );
        Ok(())
    }

    pub fn load(&mut self) -> Result<(), Errno> {
        assert_eq!(0, errno_result(unsafe { seccomp_load(self.context.as_ptr()) })?);
        Ok(())
    }
}

impl Drop for SeccompContext {
    fn drop(&mut self) {
        unsafe { seccomp_release(self.context.as_ptr()) };
    }
}

//
// internal
//

fn errno_result(result: i32) -> Result<i32, Errno> {
    if result >= 0 { Ok(result) } else { Err(Errno::from_i32(-result)) }
}
