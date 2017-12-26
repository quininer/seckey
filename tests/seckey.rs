#![cfg_attr(feature = "cargo-clippy", allow(blacklisted_name))]
#![cfg(feature = "use_std")]

extern crate seckey;

use seckey::SecKey;


#[test]
fn seckey_read_then_read() {
    let secpass = SecKey::new(1).unwrap();

    let rpass1 = secpass.read();
    let rpass2 = secpass.read();

    assert_eq!(1, *rpass1);
    assert_eq!(1, *rpass2);

    drop(rpass1);

    assert_eq!(1, *rpass2);
}

#[test]
fn seckey_drop_test() {
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
}
