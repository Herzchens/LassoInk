//! Narrow, bounded CF_UNICODETEXT copy/paste for explicit UI interactions.
//! Clipboard contents are never written to the project journal or provider.

use std::{
    io,
    mem::{align_of, size_of},
    ptr::copy_nonoverlapping,
    slice,
};

use windows_sys::Win32::{
    Foundation::{GetLastError, GlobalFree, HGLOBAL, HWND, SetLastError},
    System::{
        DataExchange::{
            CloseClipboard, EmptyClipboard, GetClipboardData, OpenClipboard, SetClipboardData,
        },
        Memory::{GMEM_MOVEABLE, GMEM_ZEROINIT, GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock},
        Ole::CF_UNICODETEXT,
    },
};

use crate::journal::{MAX_JOURNAL_TEXT_BYTES, validate_region_correction_text};

const MAX_CLIPBOARD_UTF16_UNITS: usize = MAX_JOURNAL_TEXT_BYTES * 2 + 1;
const MAX_CLIPBOARD_GLOBAL_BYTES: usize = MAX_CLIPBOARD_UTF16_UNITS * size_of::<u16>() + 64;

struct ClipboardOpenGuard {
    open: bool,
}

impl ClipboardOpenGuard {
    fn open(owner: HWND) -> io::Result<Self> {
        // SAFETY: `owner` is the live Winit window HWND supplied by the active UI callback.
        if unsafe { OpenClipboard(owner) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { open: true })
    }

    fn close(mut self) -> io::Result<()> {
        // SAFETY: this guard records one successful OpenClipboard call and closes it once.
        if unsafe { CloseClipboard() } == 0 {
            return Err(io::Error::last_os_error());
        }
        self.open = false;
        Ok(())
    }
}

impl Drop for ClipboardOpenGuard {
    fn drop(&mut self) {
        if self.open {
            // SAFETY: Drop only closes the clipboard after this guard opened it successfully.
            let _ = unsafe { CloseClipboard() };
            self.open = false;
        }
    }
}

/// Copy bounded user-visible text. `SetClipboardData` transfers ownership of
/// the unlocked movable HGLOBAL to Windows only on success; this function
/// frees it on every path where transfer did not occur.
pub(crate) fn copy_unicode_text(owner: HWND, text: &str) -> io::Result<()> {
    if owner == 0 || text.contains('\0') {
        return Err(invalid_clipboard_data());
    }
    validate_region_correction_text(text).map_err(|_| invalid_clipboard_data())?;

    let clipboard_text = windows_line_endings(text);
    let mut utf16 = clipboard_text.encode_utf16().collect::<Vec<_>>();
    if !valid_utf16_without_nul(&utf16) {
        return Err(invalid_clipboard_data());
    }
    if utf16.len() >= MAX_CLIPBOARD_UTF16_UNITS {
        return Err(invalid_clipboard_data());
    }
    utf16.push(0);
    let byte_len = utf16
        .len()
        .checked_mul(size_of::<u16>())
        .filter(|length| *length <= MAX_CLIPBOARD_UTF16_UNITS * size_of::<u16>())
        .ok_or_else(invalid_clipboard_data)?;

    // SAFETY: GlobalAlloc receives a bounded size and requests a movable global-memory block,
    // as required for clipboard data handles.
    // GMEM_ZEROINIT covers the complete exposed HGLOBAL, including allocator padding
    // beyond the requested payload, before it can be published to the clipboard.
    let hglobal = unsafe { GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, byte_len) };
    if hglobal.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: hglobal is a fresh owned block returned by GlobalAlloc above.
    let locked = unsafe { GlobalLock(hglobal) };
    if locked.is_null() {
        let error = io::Error::last_os_error();
        free_untransferred(hglobal)?;
        return Err(error);
    }
    // SAFETY: the locked allocation is at least byte_len bytes and both pointers are valid for
    // exactly utf16.len() initialized u16 elements. The NUL terminator was appended above.
    unsafe { copy_nonoverlapping(utf16.as_ptr(), locked.cast::<u16>(), utf16.len()) };
    if let Err(error) = unlock_global(hglobal) {
        free_untransferred(hglobal)?;
        return Err(error);
    }

    let clipboard = match ClipboardOpenGuard::open(owner) {
        Ok(clipboard) => clipboard,
        Err(error) => {
            free_untransferred(hglobal)?;
            return Err(error);
        }
    };
    let mut ownership_transferred = false;
    let result = (|| {
        // SAFETY: this thread owns the open clipboard guard above.
        if unsafe { EmptyClipboard() } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: hglobal remains owned by this function and contains terminated CF_UNICODETEXT.
        if unsafe { SetClipboardData(u32::from(CF_UNICODETEXT), hglobal as isize) } == 0 {
            return Err(io::Error::last_os_error());
        }
        ownership_transferred = true;
        Ok(())
    })();
    let free_result = if ownership_transferred {
        Ok(())
    } else {
        free_untransferred(hglobal)
    };
    let close_result = clipboard.close();
    result?;
    free_result?;
    close_result
}

/// Read bounded CF_UNICODETEXT into a Rust string. The clipboard's HGLOBAL is
/// borrowed while the clipboard is open, locked only for the copy, unlocked
/// before CloseClipboard, and never freed by this process.
pub(crate) fn read_unicode_text(owner: HWND) -> io::Result<Option<String>> {
    if owner == 0 {
        return Err(invalid_clipboard_data());
    }
    let clipboard = ClipboardOpenGuard::open(owner)?;
    let read_result = (|| {
        // SAFETY: the clipboard is open and owned by this guard. The returned handle is borrowed
        // from the system and remains valid only while the clipboard stays open.
        let clipboard_handle = unsafe { GetClipboardData(u32::from(CF_UNICODETEXT)) };
        if clipboard_handle == 0 {
            return Ok(None);
        }
        let hglobal = clipboard_handle as HGLOBAL;
        // SAFETY: GlobalSize inspects the system-owned clipboard memory without taking ownership.
        let byte_len = unsafe { GlobalSize(hglobal) };
        if byte_len == 0
            || byte_len % size_of::<u16>() != 0
            || byte_len > MAX_CLIPBOARD_GLOBAL_BYTES
        {
            return Err(invalid_clipboard_data());
        }
        // SAFETY: hglobal is system-owned, the clipboard guard is still open, and GlobalSize
        // supplied the exact upper bound for this lock.
        let locked = unsafe { GlobalLock(hglobal) };
        if locked.is_null() {
            return Err(io::Error::last_os_error());
        }
        if !(locked as usize).is_multiple_of(align_of::<u16>()) {
            return match unlock_global(hglobal) {
                Ok(()) => Err(invalid_clipboard_data()),
                Err(error) => Err(error),
            };
        }
        // SAFETY: `locked` was checked for u16 alignment. `byte_len` is the exact bounded
        // GlobalSize and is divisible by u16 size, so this element count fits the allocation.
        // The clipboard remains open and hglobal remains locked throughout every slice read.
        let units =
            unsafe { slice::from_raw_parts(locked.cast::<u16>(), byte_len / size_of::<u16>()) };
        let decoded = (|| {
            let Some(nul_index) = units.iter().position(|unit| *unit == 0) else {
                return Err(invalid_clipboard_data());
            };
            let content = &units[..nul_index];
            if !valid_utf16_without_nul(content) {
                return Err(invalid_clipboard_data());
            }
            let wide_text = String::from_utf16(content).map_err(|_| invalid_clipboard_data())?;
            let text = internal_line_endings(&wide_text);
            validate_region_correction_text(&text).map_err(|_| invalid_clipboard_data())?;
            Ok(Some(text))
        })();
        let unlock_result = unlock_global(hglobal);
        match (decoded, unlock_result) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(text), Ok(())) => Ok(text),
        }
    })();
    let close_result = clipboard.close();
    match (read_result, close_result) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(text), Ok(())) => Ok(text),
    }
}

fn windows_line_endings(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\r' => {
                output.push('\r');
                if characters.peek() == Some(&'\n') {
                    characters.next();
                }
                output.push('\n');
            }
            '\n' => {
                output.push('\r');
                output.push('\n');
            }
            _ => output.push(character),
        }
    }
    output
}

fn internal_line_endings(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\r' && characters.peek() == Some(&'\n') {
            characters.next();
            output.push('\n');
        } else {
            output.push(character);
        }
    }
    output
}

fn valid_utf16_without_nul(units: &[u16]) -> bool {
    let mut index = 0;
    while index < units.len() {
        let unit = units[index];
        if unit == 0 || (0xDC00..=0xDFFF).contains(&unit) {
            return false;
        }
        if (0xD800..=0xDBFF).contains(&unit) {
            if !units
                .get(index + 1)
                .is_some_and(|next| (0xDC00..=0xDFFF).contains(next))
            {
                return false;
            }
            index += 2;
        } else {
            index += 1;
        }
    }
    true
}

fn unlock_global(hglobal: HGLOBAL) -> io::Result<()> {
    // GlobalUnlock returns zero for the normal transition to an unlocked block. Clear last-error
    // first so a zero result distinguishes that normal case from an actual unlock failure.
    unsafe { SetLastError(0) };
    // SAFETY: hglobal was successfully locked once by this function's caller.
    if unsafe { GlobalUnlock(hglobal) } == 0 {
        let error = unsafe { GetLastError() };
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
    }
    Ok(())
}

fn free_untransferred(hglobal: HGLOBAL) -> io::Result<()> {
    // SAFETY: ownership has not transferred to the clipboard on every call site using this
    // helper, so this process still owns the unlocked GlobalAlloc handle.
    if !unsafe { GlobalFree(hglobal) }.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn invalid_clipboard_data() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "clipboard text is malformed or exceeds its bound",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clipboard_utf16_guard_rejects_nul_and_unpaired_surrogates() {
        assert!(valid_utf16_without_nul(&[0x0061, 0xD83D, 0xDC4B]));
        assert!(!valid_utf16_without_nul(&[0x0061, 0]));
        assert!(!valid_utf16_without_nul(&[0xD83D]));
        assert!(!valid_utf16_without_nul(&[0xDC4B]));
        assert!(!valid_utf16_without_nul(&[0xD83D, 0x0061]));
    }

    #[test]
    fn clipboard_line_conversion_preserves_existing_crlf() {
        assert_eq!(windows_line_endings("a\nb\r\nc"), "a\r\nb\r\nc");
        assert_eq!(windows_line_endings("a\rb"), "a\r\nb");
        assert_eq!(internal_line_endings("a\r\nb\nc"), "a\nb\nc");
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "guarded hosted Windows clipboard ownership and Unicode round trip"]
    fn guarded_clipboard_copy_and_paste_roundtrip_unicode_without_raw_logs() {
        crate::require_native_ui_test_opt_in();
        let class_name: Vec<u16> = "STATIC".encode_utf16().chain(Some(0)).collect();
        let title: Vec<u16> = "LassoInk clipboard fixture"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        // SAFETY: a null module handle requests the current module; no pointer is retained.
        let instance = unsafe {
            windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(std::ptr::null())
        };
        assert_ne!(instance, 0);
        // SAFETY: STATIC is a built-in window class and all output state is owned by this test.
        let hwnd = unsafe {
            windows_sys::Win32::UI::WindowsAndMessaging::CreateWindowExW(
                0,
                class_name.as_ptr(),
                title.as_ptr(),
                0,
                0,
                0,
                1,
                1,
                0,
                0,
                instance,
                std::ptr::null(),
            )
        };
        assert_ne!(hwnd, 0);
        let fixture = "NFD e\u{301}; emoji 👩‍💻\nsecond line";
        let copied = copy_unicode_text(hwnd, fixture);
        assert!(copied.is_ok());
        let pasted = read_unicode_text(hwnd).unwrap();
        assert!(
            pasted.as_deref() == Some("NFD e\u{301}; emoji 👩‍💻\nsecond line"),
            "clipboard Unicode round trip mismatch"
        );

        let allocation_checks = (|| -> io::Result<(bool, bool, bool)> {
            let clipboard = ClipboardOpenGuard::open(hwnd)?;
            let inspection = (|| {
                // SAFETY: this test owns the open clipboard guard, and copy_unicode_text just
                // published the CF_UNICODETEXT handle under test.
                let clipboard_handle = unsafe { GetClipboardData(u32::from(CF_UNICODETEXT)) };
                if clipboard_handle == 0 {
                    return Err(io::Error::last_os_error());
                }
                let hglobal = clipboard_handle as HGLOBAL;
                // SAFETY: GlobalSize reads the size of the borrowed clipboard allocation.
                let byte_len = unsafe { GlobalSize(hglobal) };
                if byte_len == 0
                    || byte_len % size_of::<u16>() != 0
                    || byte_len > MAX_CLIPBOARD_GLOBAL_BYTES
                {
                    return Err(invalid_clipboard_data());
                }
                // SAFETY: hglobal remains borrowed while the clipboard is open.
                let locked = unsafe { GlobalLock(hglobal) };
                if locked.is_null() {
                    return Err(io::Error::last_os_error());
                }
                if !(locked as usize).is_multiple_of(align_of::<u16>()) {
                    return match unlock_global(hglobal) {
                        Ok(()) => Err(invalid_clipboard_data()),
                        Err(error) => Err(error),
                    };
                }
                // SAFETY: `locked` was checked for u16 alignment. GlobalSize gives the exact
                // bounded allocation length; this slice is only read while locked and open.
                let units = unsafe {
                    slice::from_raw_parts(locked.cast::<u16>(), byte_len / size_of::<u16>())
                };
                let expected: Vec<u16> = windows_line_endings(fixture).encode_utf16().collect();
                let payload_matches = units.get(..expected.len()) == Some(expected.as_slice());
                let terminator_present = units.get(expected.len()) == Some(&0);
                let tail_is_zero = units
                    .get(expected.len() + 1..)
                    .is_some_and(|tail| tail.iter().all(|unit| *unit == 0));
                unlock_global(hglobal)?;
                Ok((payload_matches, terminator_present, tail_is_zero))
            })();
            let close_result = clipboard.close();
            match (inspection, close_result) {
                (Err(error), _) => Err(error),
                (Ok(_), Err(error)) => Err(error),
                (Ok(checks), Ok(())) => Ok(checks),
            }
        })();
        assert!(
            allocation_checks.is_ok(),
            "clipboard allocation readback failed"
        );
        let (payload_matches, terminator_present, tail_is_zero) = allocation_checks.unwrap();
        assert!(payload_matches, "copied UTF-16 payload mismatch");
        assert!(
            terminator_present,
            "copied UTF-16 payload lacks its NUL terminator"
        );
        assert!(
            tail_is_zero,
            "exposed clipboard allocation tail was not zero initialized"
        );
        // SAFETY: hwnd is the owned test window created immediately above.
        let destroyed = unsafe { windows_sys::Win32::UI::WindowsAndMessaging::DestroyWindow(hwnd) };
        assert_ne!(destroyed, 0);
    }
}
