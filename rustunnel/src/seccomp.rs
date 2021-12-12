//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

use std::convert::TryInto;
use std::ffi::CStr;
use std::ptr::NonNull;

use nix::errno::Errno;
use seccomp_sys::*;
use seccomp_sys::scmp_compare::*;

pub struct SeccompContext {
    context: NonNull<scmp_filter_ctx>,
}

#[derive(Clone, Copy, Debug)]
pub struct ArgumentComparison {
    pub index: u32,
    pub operation: ArgumentComparisonOperation,
}

#[derive(Clone, Copy, Debug)]
pub enum ArgumentComparisonOperation {
    NotEqual(u64),
    Less(u64),
    LessOrEqual(u64),
    Equal(u64),
    GreaterOrEqual(u64),
    Greater(u64),
    MaskedEqual {
        mask: u64,
        operand: u64,
    },
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
        self.allow_cmp(syscall_name, &[])?;
        Ok(())
    }

    pub fn allow_cmp<const COMPARISON_COUNT: usize>(
        &mut self,
        syscall_name: &CStr,
        argument_comparisons: &[ArgumentComparison; COMPARISON_COUNT],
    ) -> Result<(), Errno> {
        let syscall_nr = unsafe { seccomp_syscall_resolve_name(syscall_name.as_ptr()) };
        let argument_comparisons = argument_comparisons.map(From::from);
        assert_eq!(
            0,
            errno_result(unsafe {
                seccomp_rule_add_array(
                    self.context.as_ptr(),
                    SCMP_ACT_ALLOW,
                    syscall_nr,
                    argument_comparisons.len().try_into().unwrap(),
                    &argument_comparisons as *const _,
                )
            })?
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
// ArgumentComparison impls
//

impl From<ArgumentComparison> for scmp_arg_cmp {
    fn from(from: ArgumentComparison) -> Self {
        let (datum_a, datum_b, op) = match from.operation {
            ArgumentComparisonOperation::NotEqual(operand)             => (operand, 0, SCMP_CMP_NE),
            ArgumentComparisonOperation::Less(operand)                 => (operand, 0, SCMP_CMP_LT),
            ArgumentComparisonOperation::LessOrEqual(operand)          => (operand, 0, SCMP_CMP_LE),
            ArgumentComparisonOperation::Equal(operand)                => (operand, 0, SCMP_CMP_EQ),
            ArgumentComparisonOperation::GreaterOrEqual(operand)       => (operand, 0, SCMP_CMP_GE),
            ArgumentComparisonOperation::Greater(operand)              => (operand, 0, SCMP_CMP_GT),
            ArgumentComparisonOperation::MaskedEqual { mask, operand } => (mask, operand, SCMP_CMP_MASKED_EQ),
        };
        Self {
            arg: from.index,
            op,
            datum_a,
            datum_b,
        }
    }
}

//
// internal
//

fn errno_result(result: i32) -> Result<i32, Errno> {
    if result >= 0 { Ok(result) } else { Err(Errno::from_i32(-result)) }
}
