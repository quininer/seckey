extern crate seckey;

use seckey::Key;

#[test]
fn key_drop_test() {
    static mut X: usize = 0;

    struct Bar(usize);
    impl Drop for Bar {
        fn drop(&mut self) {
            unsafe {
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
        let bar = unsafe { Key::from(Bar(1)) };
        drop(bar);
    }
    assert_eq!(unsafe { X }, 1);
}
