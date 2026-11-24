//! Backward scan of one log file in windows that begin and end at record starts. Sans-IO: the caller
//! performs the reads it asks for, so the logic can be tested against an in-memory file.

use super::parse::{Entry, Format, parse_records, record_start};

/// Bytes read per step when scanning backwards.
pub const WINDOW: u64 = 1 << 20;
/// A window this large without a record start is dropped rather than read further back.
const MAX_SPAN: u64 = 16 << 20;

/// The bytes the caller must read next: `len` bytes at `offset`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Read {
    pub offset: u64,
    pub len: usize,
}

/// Scans a file from `end` back to its start, yielding each resolved window's entries newest first.
pub struct Backward {
    format: Format,
    window: u64,
    /// Exclusive end of the part not yet yielded; a record start, or the end of the file.
    end: u64,
    /// Start offset and bytes of a window being assembled; its bytes run up to `end`.
    pending: Option<(u64, Vec<u8>)>,
}

impl Backward {
    pub fn new(format: Format, end: u64, window: u64) -> Backward {
        Backward {
            format,
            window: window.max(1),
            end,
            pending: None,
        }
    }

    /// Offset up to which the file has been yielded; a record start, and where a cursor resumes.
    pub fn end(&self) -> u64 {
        self.end
    }

    /// The next read needed, or None when the start of the file has been reached.
    pub fn request(&self) -> Option<Read> {
        if self.end == 0 {
            return None;
        }
        match &self.pending {
            None => {
                let len = self.end.min(self.window);
                Some(Read {
                    offset: self.end - len,
                    len: len as usize,
                })
            }
            Some((start, _)) => {
                let len = (*start).min(self.window);
                Some(Read {
                    offset: start - len,
                    len: len as usize,
                })
            }
        }
    }

    /// Supplies the bytes requested by `request`. Returns the entries of a resolved window, newest
    /// first, each with its absolute byte offset; None while the window needs more bytes.
    pub fn feed(&mut self, offset: u64, bytes: Vec<u8>) -> Option<Vec<(u64, Entry)>> {
        let (start, buf) = match self.pending.take() {
            None => (offset, bytes),
            Some((_, mut rest)) => {
                let mut joined = bytes;
                joined.append(&mut rest);
                (offset, joined)
            }
        };
        let from = if start == 0 {
            Some(0)
        } else {
            first_record_start(self.format, &buf)
        };
        match from {
            Some(index) => {
                let base = start + index as u64;
                let records = parse_records(self.format, &buf[index..]);
                self.end = base;
                Some(
                    records
                        .into_iter()
                        .rev()
                        .map(|(at, entry)| (base + at as u64, entry))
                        .collect(),
                )
            }
            None if self.end - start >= MAX_SPAN => {
                // No record start within the span: its bytes are dropped.
                self.end = start;
                Some(Vec::new())
            }
            None => {
                self.pending = Some((start, buf));
                None
            }
        }
    }
}

/// Index of the first record start inside `buf` (one that follows a newline in the buffer).
fn first_record_start(format: Format, buf: &[u8]) -> Option<usize> {
    (1..buf.len()).find(|&p| buf[p - 1] == b'\n' && record_start(format, &buf[p..]))
}

#[cfg(test)]
mod tests {
    use super::{Backward, Format, Read};
    use crate::tools::logs::parse::{Entry, parse_records};

    /// Drives the scanner over `data` from `end` with the given window and returns newest-first entries.
    fn drive(format: Format, data: &[u8], end: u64, window: u64) -> Vec<(u64, Entry)> {
        let mut scan = Backward::new(format, end, window);
        let mut out = Vec::new();
        while let Some(Read { offset, len }) = scan.request() {
            let start = offset as usize;
            let bytes = data[start..start + len].to_vec();
            if let Some(entries) = scan.feed(offset, bytes) {
                out.extend(entries);
            }
        }
        out
    }

    fn samples() -> Vec<(Format, String)> {
        vec![
            (
                Format::Jsonlog,
                "{\"timestamp\":\"2026-01-31 14:00:00.000 UTC\",\"error_severity\":\"LOG\",\"message\":\"one\"}\n\
                 {\"timestamp\":\"2026-01-31 14:00:01.000 UTC\",\"error_severity\":\"ERROR\",\"message\":\"two\"}\n\
                 {\"timestamp\":\"2026-01-31 14:00:02.000 UTC\",\"error_severity\":\"LOG\",\"message\":\"three\"}\n"
                    .to_owned(),
            ),
            (
                Format::Csvlog,
                "2026-01-31 14:00:00.000 UTC,u,d,1,,s,1,,,,,LOG,00000,\"one\",,,,,,,,,,,,\n\
                 2026-01-31 14:00:01.000 UTC,u,d,2,,s,1,,,,,ERROR,22012,\"two\nline\",,,,,,,,,,,,\n\
                 2026-01-31 14:00:02.000 UTC,u,d,3,,s,1,,,,,LOG,00000,\"three, \"\"q\"\"\",,,,,,,,,,,,\n"
                    .to_owned(),
            ),
            (
                Format::Stderr,
                "2026-01-31 14:00:00.000 UTC [1] LOG:  one\n\
                 2026-01-31 14:00:01.000 UTC [2] ERROR:  two\n\
                 2026-01-31 14:00:01.000 UTC [2] DETAIL:  two detail\n\
                 continued\n\
                 2026-01-31 14:00:01.000 UTC [2] STATEMENT:  SELECT 2\n\
                 2026-01-31 14:00:02.000 UTC [3] LOG:  three\n\
                 more\n"
                    .to_owned(),
            ),
        ]
    }

    #[test]
    fn every_window_size_matches_a_whole_parse() {
        for (format, text) in samples() {
            let data = text.as_bytes();
            let mut expected = parse_records(format, data);
            expected.reverse();
            let end = data.len() as u64;
            for window in 1..=(data.len() as u64 + 1) {
                let got = drive(format, data, end, window);
                let want: Vec<(u64, Entry)> = expected
                    .iter()
                    .map(|(at, entry)| (*at as u64, entry.clone()))
                    .collect();
                assert_eq!(got, want, "format {format:?}, window {window}");
            }
        }
    }

    #[test]
    fn resuming_from_an_entry_start_returns_only_older_entries() {
        for (format, text) in samples() {
            let data = text.as_bytes();
            let parsed = parse_records(format, data);
            for (index, (at, _)) in parsed.iter().enumerate() {
                let got = drive(format, data, *at as u64, 7);
                let mut want: Vec<(u64, Entry)> = parsed[..index]
                    .iter()
                    .map(|(at, entry)| (*at as u64, entry.clone()))
                    .collect();
                want.reverse();
                assert_eq!(got, want, "format {format:?}, resume at entry {index}");
            }
        }
    }

    #[test]
    fn empty_range_requests_nothing() {
        let scan = Backward::new(Format::Stderr, 0, 16);
        assert_eq!(scan.request(), None);
    }
}
