//
// Copyright (C) 2019, 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//

//! Logging utilities for use with a sandboxed process.

use std::io;
use std::io::prelude::*;

/// An implementation of [`log::Log`] suitable for use with `rustunnel`.
///
/// A process utilizing `rustunnel` is meant to be a sandboxed, minimal child process, with a limited set of system
/// calls available to it. This prevents, for example, reading the system time, and thus this implementation does not
/// print log message timestamps. Furthermore, this logger's output is meant to be parsed using [`Logger::parse_line`]
/// by a parent process, so only the log level and message are printed. The output is printed to to standard error.
pub struct Logger {
    /// The maximum log level to output.
    pub level: log::Level,
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let log_level_string = match record.level() {
                log::Level::Error => "ERRO",
                log::Level::Warn => "WARN",
                log::Level::Info => "INFO",
                log::Level::Debug => "DEBG",
                log::Level::Trace => "TRCE",
            };
            let line = format!("{:<4} {}\n", log_level_string, record.args());
            let _ignore = write!(io::stderr(), "{}", line);
        }
    }

    fn flush(&self) {}
}

impl Logger {
    /// Parse a log line printed by [`Logger`] into a [`log::Level`] and a log message string.
    pub fn parse_line(line: &str) -> (log::Level, &str) {
        match line.get(..5) {
            Some("ERRO ") => (log::Level::Error, line.get(5..).unwrap_or_else(|| unreachable!())),
            Some("WARN ") => (log::Level::Warn, line.get(5..).unwrap_or_else(|| unreachable!())),
            Some("INFO ") => (log::Level::Info, line.get(5..).unwrap_or_else(|| unreachable!())),
            Some("DEBG ") => (log::Level::Debug, line.get(5..).unwrap_or_else(|| unreachable!())),
            Some("TRCE ") => (log::Level::Trace, line.get(5..).unwrap_or_else(|| unreachable!())),
            _ => (log::Level::Info, &line[..]),
        }
    }
}
