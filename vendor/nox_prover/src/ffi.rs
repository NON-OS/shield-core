// NONOS Operating System (AGPL-3.0-or-later)
//! The C interface, for an iOS, Android or desktop app.
//!
//! ```text
//! int32_t nox_prove(const char *request, const char *seed,
//!                   const uint8_t *entropy, size_t entropy_len,
//!                   char **out);
//! void nox_free(char *s);
//! ```
//!
//! `nox_prove` returns 0 and sets `*out` to the proof as JSON (`to_json`), or
//! returns 1 and sets `*out` to the reason. Either string belongs to the
//! caller, who hands it back to `nox_free`. A null argument returns 2 and sets
//! nothing. The JSON holds the spender's new secrets: wipe it after storing it.

use core::ffi::c_char;
use std::ffi::{CStr, CString};

fn owned_c(s: String) -> *mut c_char {
    // An interior NUL cannot come out of `to_json` or an error message; if it
    // ever did, the caller gets an empty string rather than a truncated one.
    CString::new(s).unwrap_or_default().into_raw()
}

/// # Safety
/// `request` and `seed` are NUL-terminated UTF-8, `entropy` points to
/// `entropy_len` readable bytes, and `out` is writable.
#[no_mangle]
pub unsafe extern "C" fn nox_prove(
    request: *const c_char,
    seed: *const c_char,
    entropy: *const u8,
    entropy_len: usize,
    out: *mut *mut c_char,
) -> i32 {
    if request.is_null() || seed.is_null() || entropy.is_null() || out.is_null() {
        return 2;
    }
    // SAFETY: non-null, and the caller's contract is NUL-terminated strings
    // and `entropy_len` readable bytes.
    let (req, sd, ent) = unsafe {
        (
            CStr::from_ptr(request).to_str(),
            CStr::from_ptr(seed).to_str(),
            core::slice::from_raw_parts(entropy, entropy_len),
        )
    };
    let result = match (req, sd) {
        (Ok(r), Ok(s)) => crate::prove(r, s, ent).map(|p| crate::to_json(&p)),
        _ => Err("the request or the seed is not UTF-8".to_string()),
    };
    let (code, text) = match result {
        Ok(json) => (0, json),
        Err(why) => (1, why),
    };
    // SAFETY: `out` is non-null and writable by the caller's contract.
    unsafe { *out = owned_c(text) };
    code
}

/// Result codes of the extended interface, one per `Error` kind.
pub const NOX_OK: i32 = 0;
pub const NOX_ERR_REQUEST: i32 = 1;
pub const NOX_ERR_POLICY: i32 = 2;
pub const NOX_ERR_ENTROPY: i32 = 3;
pub const NOX_ERR_CACHE: i32 = 4;
pub const NOX_ERR_CIRCUIT: i32 = 5;
pub const NOX_ERR_NOT_VERIFIED: i32 = 6;
pub const NOX_ERR_CANCELLED: i32 = 7;
pub const NOX_ERR_NULL: i32 = 8;
pub const NOX_ERR_RANK: i32 = 9;

/// The code lives on `Error` so the Rust, C and wallet interfaces share one
/// numbering; the constants above name the same values for C callers.
fn code(e: &crate::Error) -> i32 {
    e.code()
}

/// A progress callback from C: the phase number (the order of `Phase`,
/// 0 to 10), the fraction of the proof done, and the caller's context.
pub type NoxProgress =
    Option<unsafe extern "C" fn(ctx: *mut core::ffi::c_void, phase: u32, fraction: f32)>;

struct Ctx(*mut core::ffi::c_void);
// SAFETY: the pointer is the caller's and only handed back to the caller's
// own callback; the caller's contract is that the callback may run on any
// thread.
unsafe impl Sync for Ctx {}

struct CancelByte(*const u8);
// SAFETY: the byte is only read, volatile, and the caller's contract keeps it
// alive for the call; a stale read only delays the stop by one phase.
unsafe impl Sync for CancelByte {}

/// Prove with the bundled cache, progress and cancellation.
///
/// Returns `NOX_OK` and sets `*out` to the proof JSON, or an error code and
/// sets `*out` to the reason. `cancel`, when not null, is polled between
/// phases: set the byte it points to nonzero to stop.
///
/// # Safety
/// Strings are NUL-terminated UTF-8; `entropy` and `cache` point to their
/// lengths in readable bytes; `cancel` is null or points to a byte that lives
/// for the call; `out` is writable; `progress`, when given, may be called
/// from any thread.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn nox_prove_ex(
    request: *const c_char,
    seed: *const c_char,
    entropy: *const u8,
    entropy_len: usize,
    cache: *const u8,
    cache_len: usize,
    progress: NoxProgress,
    ctx: *mut core::ffi::c_void,
    cancel: *const u8,
    out: *mut *mut c_char,
) -> i32 {
    if request.is_null() || seed.is_null() || entropy.is_null() || cache.is_null() || out.is_null()
    {
        return NOX_ERR_NULL;
    }
    // SAFETY: non-null, and the caller's contract gives the lengths.
    let (req, sd, ent, cch) = unsafe {
        (
            CStr::from_ptr(request).to_str(),
            CStr::from_ptr(seed).to_str(),
            core::slice::from_raw_parts(entropy, entropy_len),
            core::slice::from_raw_parts(cache, cache_len),
        )
    };
    let (Ok(req), Ok(sd)) = (req, sd) else {
        // SAFETY: `out` is non-null and writable.
        unsafe { *out = owned_c("the request or the seed is not UTF-8".to_string()) };
        return NOX_ERR_REQUEST;
    };
    let flag = core::sync::atomic::AtomicBool::new(false);
    let (ctx, cancel) = (&Ctx(ctx), &CancelByte(cancel));
    let report = |p: crate::Phase, f: f32| {
        let (ctx, cancel) = (ctx, cancel);
        if let Some(cb) = progress {
            // SAFETY: the caller's callback and context, per the contract.
            unsafe { cb(ctx.0, p as u32, f) };
        }
        // SAFETY: `cancel` is null or a live byte, per the contract.
        if !cancel.0.is_null() && unsafe { core::ptr::read_volatile(cancel.0) } != 0 {
            flag.store(true, core::sync::atomic::Ordering::Relaxed);
        }
    };
    let opts = crate::Options {
        cache: Some(cch),
        progress: Some(&report),
        cancel: Some(&flag),
    };
    let (rc, text) = match crate::prove_with(req, sd, ent, &opts) {
        Ok((proof, _)) => (NOX_OK, crate::to_json(&proof)),
        Err(e) => (code(&e), e.to_string()),
    };
    // SAFETY: `out` is non-null and writable.
    unsafe { *out = owned_c(text) };
    rc
}

/// Verify a proof against its 36 public words and the bundled cache.
/// Returns `NOX_OK` or an error code.
///
/// # Safety
/// `proof` and `cache` point to their lengths in readable bytes, `publics`
/// to `n_publics` readable u64s.
#[no_mangle]
pub unsafe extern "C" fn nox_verify(
    proof: *const u8,
    proof_len: usize,
    publics: *const u64,
    n_publics: usize,
    cache: *const u8,
    cache_len: usize,
) -> i32 {
    if proof.is_null() || publics.is_null() || cache.is_null() {
        return NOX_ERR_NULL;
    }
    // SAFETY: non-null, and the caller's contract gives the lengths.
    let (p, w, c) = unsafe {
        (
            core::slice::from_raw_parts(proof, proof_len),
            core::slice::from_raw_parts(publics, n_publics),
            core::slice::from_raw_parts(cache, cache_len),
        )
    };
    match crate::verify(p, w, c) {
        Ok(()) => NOX_OK,
        Err(e) => code(&e),
    }
}

/// # Safety
/// `s` is null or a string `nox_prove` or `nox_prove_ex` returned, not yet
/// freed.
#[no_mangle]
pub unsafe extern "C" fn nox_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    // SAFETY: `s` came from `CString::into_raw` in `owned_c`.
    let mut owned = unsafe { CString::from_raw(s) }.into_bytes();
    owned.fill(0);
}
