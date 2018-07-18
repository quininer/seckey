#![cfg_attr(feature = "cargo-clippy", allow(blacklisted_name))]


extern crate seckey;

use seckey::{ TempKey, CmpKey };


#[test]
fn cmpkey_cmp_test() {
    assert!(CmpKey(1) > 0);
    assert!(CmpKey(0) < 1);
    assert_eq!(CmpKey(0), 0);
    assert_ne!(CmpKey(1), 0);

    assert!(CmpKey(-1) > 0);
        // ^- NOTE 4294967295 > 0

    let a = [2; 3];
    let b = [1; 4];
    assert_eq!(&a[..] > &b[..], CmpKey::from(&a[..]) > CmpKey::from(&b[..]));
}

#[test]
fn tempkey_slice_test() {
    // fixed size
    let mut key = [42u32; 8];

    {
        let mut tempkey = TempKey::from(&mut key);
        assert_eq!(CmpKey::from(&*tempkey), &[42u32; 8]);

        tempkey[1] = 0;
        assert_eq!(CmpKey::from(&*tempkey), &[42u32, 0, 42, 42, 42, 42, 42, 42]);
    }

    assert_eq!(key, [0; 8]);

    // dyn size
    let mut key = [42u32; 8];

    {
        let mut tempkey = TempKey::from(&mut key[1..7]);
        assert_eq!(CmpKey::from(&*tempkey), &[42; 6][..]);

        tempkey[1] = 0;
        assert_eq!(CmpKey::from(&*tempkey), &[42, 0, 42, 42, 42, 42][..]);
    }

    assert_eq!(&key[1..7], [0; 6]);
    assert_eq!(key[0], 42);
    assert_eq!(key[7], 42);

    // dyn size x2
    let mut key = [[41u32; 3], [42u32; 3], [43u32; 3], [44u32; 3]];

    {
        let mut tempkey = TempKey::from(&mut key[1..3]);
        assert_eq!(CmpKey::from(&tempkey[0][..]), &[42u32; 3][..]);

        tempkey[1][1] = 24;
        assert_eq!(CmpKey::from(&tempkey[1][1]), &24);
    }

    assert_eq!(key[0], [41; 3]);
    assert_eq!(key[1], [0; 3]);
    assert_eq!(key[2], [0; 3]);
    assert_eq!(key[3], [44; 3]);

    {
        let tempkey = TempKey::from(&mut key);
        assert_eq!(CmpKey::from(&tempkey[0][0]), &41);
    }
    assert_eq!(key, [[0; 3]; 4]);
}

#[test]
fn tempkey_from_str() {
    let mut bar = String::from("bar");
    {
        let bar = TempKey::from(&mut bar as &mut str);
        assert_eq!(CmpKey::from(&*bar), "bar");
        assert_ne!(CmpKey::from(&*bar), "rab");
    }
    assert_eq!(bar, String::from_utf8(vec![0x00, 0x00, 0x00]).unwrap());


    let mut bar2 = String::from("barbarbar");
    {
        let bar2 = TempKey::from(&mut bar2[3..][..3]);
        assert_eq!(CmpKey::from(&*bar2), "bar");
    }
    assert!(bar2.starts_with("bar"));
    assert!(bar2.ends_with("bar"));
    assert_eq!(&bar2[3..][..3], String::from_utf8(vec![0x00, 0x00, 0x00]).unwrap());
}
