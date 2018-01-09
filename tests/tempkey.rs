#![cfg_attr(feature = "cargo-clippy", allow(blacklisted_name))]


extern crate seckey;

use seckey::TempKey;

#[test]
fn tempkey_cmp_test() {
    let mut one: i32 = 1;
    let mut zero: i32 = 0;
    let mut negative_one: i32 = -1;

    assert!(TempKey::new(&mut one) > 0);
    assert!(TempKey::new(&mut zero) < 1);
    assert_eq!(TempKey::new(&mut zero), 0);

    assert!(TempKey::new(&mut negative_one) > 0);
        // ^- NOTE 4294967295 > 0
}

#[test]
fn tempkey_slice_test() {
    let mut key = [42u8; 8];

    {
        let mut tempkey = TempKey::new(&mut key);
        assert_eq!(tempkey, [42; 8]);

        tempkey[1] = 0;
        assert_eq!(tempkey, [42, 0, 42, 42, 42, 42, 42, 42]);
    }

    assert_eq!(key, [0; 8]);
}

#[test]
fn tempkey_try_form_test() {
    struct Bar(());
    struct Bar2(());

    impl Drop for Bar2 {
        fn drop(&mut self) {}
    }

    let mut bar = Bar(());
    let mut bar2 = Bar2(());

    assert!(TempKey::try_from(&mut bar).is_ok());
    assert!(TempKey::try_from(&mut bar2).is_err());
}
