#![cfg_attr(feature = "cargo-clippy", allow(blacklisted_name))]


extern crate seckey;

use seckey::TempKey;

#[test]
fn tempkey_cmp_test() {
    let mut one: i32 = 1;
    let mut zero: i32 = 0;
    let mut negative_one: i32 = -1;

    assert!(TempKey::from(&mut one) > 0);
    assert!(TempKey::from(&mut zero) < 1);
    assert_eq!(TempKey::from(&mut zero), 0);

    assert!(TempKey::from(&mut negative_one) > 0);
        // ^- NOTE 4294967295 > 0
}

#[test]
fn tempkey_slice_test() {
    // fixed size
    let mut key = [42u32; 8];

    {
        let mut tempkey = TempKey::from(&mut key);
        assert_eq!(tempkey, [42; 8]);

        tempkey[1] = 0;
        assert_eq!(tempkey, [42, 0, 42, 42, 42, 42, 42, 42]);
    }

    assert_eq!(key, [0; 8]);


    // dyn size
    let mut key = [42u32; 8];

    {
        let mut tempkey = TempKey::from(&mut key[1..7]);
        assert_eq!(tempkey, [42; 6][..]);

        tempkey[1] = 0;
        assert_eq!(tempkey, [42, 0, 42, 42, 42, 42][..]);
    }

    assert_eq!(&key[1..7], [0; 6]);
    assert_eq!(key[0], 42);
    assert_eq!(key[7], 42);

    // dyn size x2
    let mut key = [[42u32; 3], [42u32; 3], [42u32; 3]];

    {
        let mut tempkey = TempKey::from(&mut key[1..2]);
        assert_eq!(tempkey[0], &mut [42; 3][..]);

        tempkey[0][1] = 24;
        assert_eq!(tempkey[0][1], 24);
    }

    assert_eq!(key[0], [42; 3]);
    assert_eq!(key[1], [0; 3]);
    assert_eq!(key[2], [42; 3]);

    {
        let tempkey = TempKey::from(&mut key);
        assert_eq!(tempkey[0][0], 42);
    }
    assert_eq!(key, [[0; 3]; 3]);
}

#[test]
fn tempkey_from_str() {
    let mut bar = String::from("bar");
    {
        let bar = TempKey::from(&mut bar as &mut str);
        assert_eq!(&*bar, "bar");
    }
    assert_eq!(bar, String::from_utf8(vec![0x00, 0x00, 0x00]).unwrap());


    let mut bar2 = String::from("barbarbar");
    {
        let bar2 = TempKey::from(&mut bar2[3..][..3]);
        assert_eq!(&*bar2, "bar");
    }
    assert!(bar2.starts_with("bar"));
    assert!(bar2.ends_with("bar"));
    assert_eq!(&bar2[3..][..3], String::from_utf8(vec![0x00, 0x00, 0x00]).unwrap());
}
