#![cfg_attr(feature = "cargo-clippy", allow(blacklisted_name))]


extern crate seckey;

use seckey::{ TempKey, CmpKey };


#[test]
fn cmpkey_cmp_test() {
    #[derive(Debug)]
    struct I32Array([u8; 4]);

    impl I32Array {
        fn new(n: i32) -> I32Array {
            I32Array(n.to_le_bytes())
        }
    }

    impl AsRef<[u8]> for I32Array {
        fn as_ref(&self) -> &[u8] {
            &self.0[..]
        }
    }

    assert!(CmpKey(I32Array::new(1)) > I32Array::new(0));
    assert!(CmpKey(I32Array::new(0)) < I32Array::new(1));
    assert_eq!(CmpKey(I32Array::new(0)), I32Array::new(0));
    assert_ne!(CmpKey(I32Array::new(1)), I32Array::new(0));

    assert!(CmpKey(I32Array::new(-1)) > I32Array::new(0));
        // ^- NOTE 4294967295 > 0

    let a = [2; 3];
    let b = [1; 4];
    assert_eq!(&a[..] > &b[..], CmpKey(&a[..]) > CmpKey(&b[..]));
}

#[test]
fn tempkey_slice_test() {
    // fixed size
    let mut key = [42u8; 32];

    {
        let mut tempkey = TempKey::new(&mut key);
        assert_eq!(CmpKey(&tempkey[..]), &[42u8; 32][..]);

        tempkey[1] = 0;
        let mut res = [42u8; 32];
        res[1] = 0;
        assert_eq!(CmpKey(&tempkey[..]), &res[..]);
    }

    assert_eq!(key, [0; 32]);

    // dyn size
    let mut key = [42u8; 32];

    {
        let mut tempkey = TempKey::new(&mut key[1..7]);
        assert_eq!(CmpKey(&tempkey[..]), &[42; 6][..]);

        tempkey[1] = 0;
        assert_eq!(CmpKey(&tempkey[..]), &[42, 0, 42, 42, 42, 42][..]);
    }

    assert_eq!(&key[1..7], [0; 6]);
    assert_eq!(key[0], 42);
    assert_eq!(key[7], 42);
}
