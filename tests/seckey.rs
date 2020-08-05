#![cfg(feature = "use_std")]

use seckey::SecBytes;


#[test]
fn seckey_read_then_read() {
    let secpass = SecBytes::with(1, |buf| buf[0] = 1);

    let rpass1 = secpass.read();
    let rpass2 = secpass.read();

    assert_eq!(1, rpass1[0]);
    assert_eq!(1, rpass2[0]);

    drop(rpass1);

    assert_eq!(1, rpass2[0]);
}

#[test]
fn test_readme() {
    let mut secpass = SecBytes::with(8, |buf| buf.copy_from_slice(&[8; 8][..]));

    {
        assert_eq!([8u8; 8], *secpass.read());
    }

    {
        let mut wpass = secpass.write();
        wpass[0] = 0;
        assert_eq!([0, 8, 8, 8, 8, 8, 8, 8], *wpass);
    }
}
