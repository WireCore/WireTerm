//! How long nothing has been typed on the computer.
//!
//! The vault closes after a quarter of an hour. What is meant is a quarter of
//! an hour in which nobody was at the computer — not one in which WireTerm had
//! nothing to do. Someone working next door in another window should not come
//! back and have to type their master password again.
//!
//! Windows answers the question with `GetLastInputInfo`: keyboard and mouse
//! of the own session, across all windows. Where the operating system gives
//! no answer, the old measure stays — when the vault was last worked with,
//! see [`super::account::Unlocked`].

use std::time::Duration;

/// How long ago the last input was.
///
/// `None` does not mean "just now" but "this platform does not say".
/// The caller decides what to use instead.
#[cfg(windows)]
pub fn since_last_input() -> Option<Duration> {
    /// What `GetLastInputInfo` fills in. `cb_size` is only read by the API.
    #[allow(dead_code)]
    #[repr(C)]
    struct LastInputInfo {
        cb_size: u32,
        time: u32,
    }

    #[link(name = "user32")]
    extern "system" {
        fn GetLastInputInfo(info: *mut LastInputInfo) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetTickCount() -> u32;
    }

    let mut info = LastInputInfo {
        cb_size: std::mem::size_of::<LastInputInfo>() as u32,
        time: 0,
    };

    // SAFETY: `info` lives on the stack for the duration of the call, is
    // fully initialized and `cb_size` tells the API how large it is.
    // It is only written into, not beyond.
    if unsafe { GetLastInputInfo(&mut info) } == 0 {
        return None;
    }

    // Both values count milliseconds since boot and wrap around together
    // after 49.7 days. `wrapping_sub` gives the right distance across that
    // edge as well.
    let since = unsafe { GetTickCount() }.wrapping_sub(info.time);
    Some(Duration::from_millis(u64::from(since)))
}

#[cfg(not(windows))]
pub fn since_last_input() -> Option<Duration> {
    None
}
