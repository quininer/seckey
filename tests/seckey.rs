extern crate seckey;
#[cfg(unix)] extern crate nix;

use std::slice;
use seckey::SecKey;


#[cfg(all(unix, not(any(target_os = "macos", target_os = "ios"))))]
#[should_panic]
#[test]
fn protect_seckey_test() {
    use nix::sys::signal;
    extern fn sigsegv(_: i32) { panic!() }
    let sigaction = signal::SigAction::new(
        signal::SigHandler::Handler(sigsegv),
        signal::SA_SIGINFO,
        signal::SigSet::empty(),
    );
    unsafe { signal::sigaction(signal::SIGSEGV, &sigaction).ok() };

    let mut secpass = SecKey::new(&[1; 8]).unwrap();

    let (bs_ptr, bs_len) = secpass.write_map(|bs| (bs.as_mut_ptr(), bs.len())); // violence get secpass ptr
    let bs_bytes = unsafe { slice::from_raw_parts_mut(bs_ptr, bs_len) };
    bs_bytes[0] = 0; // SIGSEGV !
}
