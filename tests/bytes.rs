extern crate seckey;

use seckey::Bytes;


#[test]
fn bytes_eq_test() {
    let x = Bytes::new(&[3; 16]);
    let y = Bytes::new(&[2; 16]);
    let z = [3; 16];

    assert_ne!(x, y);
    assert_eq!(x, z);
    assert_eq!(x, Bytes::new(&z));
    assert_ne!(x, Bytes::new(&y));
}
