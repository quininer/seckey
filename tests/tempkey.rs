#![cfg_attr(feature = "cargo-clippy", allow(blacklisted_name))]


extern crate seckey;

use seckey::TempKey;

#[test]
fn tempkey_cmp_test() {
    let mut one: i32 = 1;
    let mut one2: i32 = 1;
    let mut one3: i32 = 1;
    let mut zero: i32 = 0;
    let mut negative_one: i32 = -1;

    assert!(TempKey::new(&mut one) > 0);
    assert!(TempKey::new(&mut zero) < 1);
    assert_eq!(TempKey::new(&mut zero), 0);

    assert!(TempKey::new(&mut negative_one) > 0);
        // ^- NOTE 4294967295 > 0

    assert_eq!(TempKey::new(&mut one2), TempKey::new(&mut one3));
}

#[test]
fn tempkey_slice_test() {
    // fixed size
    let mut key = [42u32; 8];

    {
        let mut tempkey = TempKey::new(&mut key);
        assert_eq!(tempkey, [42; 8]);

        tempkey[1] = 0;
        assert_eq!(tempkey, [42, 0, 42, 42, 42, 42, 42, 42]);
    }

    assert_eq!(key, [0; 8]);


    // dyn size
    let mut key = [42u32; 8];

    {
        let mut tempkey = TempKey::from_slice(&mut key[1..7]);
        assert_eq!(tempkey, [42; 6][..]);

        tempkey[1] = 0;
        assert_eq!(tempkey, [42, 0, 42, 42, 42, 42][..]);
    }

    assert_eq!(&key[1..7], [0; 6]);
    assert_eq!(key[0], 42);
    assert_eq!(key[7], 42);
}

#[test]
fn tempkey_try_form_test() {
    struct Bar<T>(T);
    struct Bar2<T>(T);

    impl<T> Drop for Bar2<T> {
        fn drop(&mut self) {}
    }

    let mut bar = Bar(());
    let mut bar2 = Bar2(());
    let mut bar3 = Bar(Bar2(()));
    let mut bar_slice = [Bar(()), Bar(()), Bar(())];
    let mut bar_slice2 = [Bar2(()), Bar2(()), Bar2(())];

    assert!(TempKey::try_from(&mut bar).is_ok());
    assert!(TempKey::try_from(&mut bar2).is_err());
    assert!(TempKey::try_from(&mut bar3).is_err());
    assert!(TempKey::try_from_slice(&mut bar_slice[..]).is_ok());
    assert!(TempKey::try_from_slice(&mut bar_slice2[..]).is_err());
}
