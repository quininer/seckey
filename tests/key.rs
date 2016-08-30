extern crate seckey;

use seckey::Key;


#[test]
fn key_eq_test() {
    let x = Key::new([3; 16]);
    let y = Key::new([2; 16]);
    let z = [3; 16];

    assert!(x != y);
    assert_eq!(x, z);
    assert_eq!(x, Key::new(z));
    assert!(x != Key::new(y));
}
