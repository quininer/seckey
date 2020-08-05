use seckey::free;


#[test]
fn free_test_ref() {
    pub struct Bar(u32);

    impl Drop for Bar {
        fn drop(&mut self) {
            assert_eq!(self.0, 0x42);
            self.0 += 1;
        }
    }

    let mut bar = Bar(0x42);

    {
        free(&mut bar);
    }

    assert_eq!(bar.0, 0x42);
}

#[test]
fn free_test_drop() {
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
        free(bar);
    }
    assert_eq!(unsafe { X }, 1);

    {
        let bar = Bar(3);
        free(&bar);
    }
    assert_eq!(unsafe { X }, 2);

    {
        let baz = Baz(Bar(3));
        free(baz);
    }
    assert_eq!(unsafe { X }, 3);
}
