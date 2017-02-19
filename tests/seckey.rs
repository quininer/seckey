#![cfg_attr(feature = "place", feature(placement_in_syntax))]

extern crate seckey;
#[cfg(unix)] extern crate nix;

use std::slice;
use seckey::SecKey;


#[cfg(feature = "place")]
#[cfg(all(unix, not(any(target_os = "macos", target_os = "ios"))))]
#[should_panic]
#[test]
fn place_protect_seckey_test() {
    use seckey::SecHeap;
    use nix::sys::signal;
    extern fn sigsegv(_: i32) { panic!() }
    let sigaction = signal::SigAction::new(
        signal::SigHandler::Handler(sigsegv),
        signal::SA_SIGINFO,
        signal::SigSet::empty(),
    );
    unsafe { signal::sigaction(signal::SIGSEGV, &sigaction).ok() };

    let mut secpass = SecHeap <- [1; 8];

    let mut wpass = secpass.write();
    let bs_bytes = unsafe {
        // unsafe get secpass ptr
        slice::from_raw_parts_mut(wpass.as_mut_ptr(), wpass.len())
    };
    drop(wpass);
    bs_bytes[0] = 0; // SIGSEGV !
}

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

    let mut secpass = SecKey::new([1; 8]).unwrap();

    let mut wpass = secpass.write();
    let bs_bytes = unsafe {
        // unsafe get secpass ptr
        slice::from_raw_parts_mut(wpass.as_mut_ptr(), wpass.len())
    };
    drop(wpass);
    bs_bytes[0] = 0; // SIGSEGV !
}

#[test]
fn seckey_read_then_read() {
    let secpass = SecKey::new(1).unwrap();

    let rpass1 = secpass.read();
    let rpass2 = secpass.read();

    assert_eq!(1, *rpass1);
    assert_eq!(1, *rpass2);

    drop(rpass1);

    assert_eq!(1, *rpass2);

    #[cfg(feature = "place")]   {
        use seckey::SecHeap;

        let secpass = SecHeap <- 1;

        let rpass1 = secpass.read();
        let rpass2 = secpass.read();

        assert_eq!(1, *rpass1);
        assert_eq!(1, *rpass2);

        drop(rpass1);

        assert_eq!(1, *rpass2);
    }
}

#[test]
fn seckey_drop() {
    static mut X: usize = 0;

    #[derive(Debug)] struct Bar(usize);
    #[derive(Debug)] struct Baz<T>(T);
    impl Drop for Bar {
        fn drop(&mut self) {
            unsafe {
                X += 1;
                assert_eq!(
                    self.0,
                    if X == 2 { 3 } else { X }
                );
            }
        }
    }

    {
        let bar = Bar(1);
        let bar2 = SecKey::new(bar).unwrap();
        drop(bar2);
    }
    assert_eq!(unsafe { X }, 1);

    {
        let bar = Bar(3);
        let bar3 = unsafe { SecKey::from_raw(&bar).unwrap() };
        drop(bar);
        drop(bar3);
    }
    assert_eq!(unsafe { X }, 3);

    {
        let baz = Baz(Bar(4));
        let baz2 = SecKey::new(baz).unwrap();
        drop(baz2);
    }
    assert_eq!(unsafe { X }, 4);

    #[cfg(feature = "place")] {
        use seckey::SecHeap;

        {
            let bar5 = SecHeap <- Bar(5);
            drop(bar5);
        }
        assert_eq!(unsafe { X }, 5);
    }
}
