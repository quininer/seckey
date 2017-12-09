extern crate seckey;

use seckey::TempKey;

#[test]
fn key_cmp_test() {
    assert!(TempKey::from(1) > 0);
    assert!(TempKey::from(0) < 1);
    assert_eq!(TempKey::from(0), 0);

    assert!(TempKey::from(-1) > 0);
        // ^- NOTE 4294967295 > 0
}

#[test]
fn key_drop_test() {
    static mut X: usize = 0;

    struct Bar(usize);
    impl Drop for Bar {
        fn drop(&mut self) {
            unsafe {
                assert_ne!(self.0, 0);
                X += self.0;
            }
        }
    }

    {
        let bar = Bar(1);
        drop(bar);
    }
    assert_eq!(unsafe { X }, 1);

    {
        let bar = TempKey::from(Bar(1));
        drop(bar);
    }
    assert_eq!(unsafe { X }, 2);
}
