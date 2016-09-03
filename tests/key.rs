extern crate seckey;

use seckey::Key;


#[test]
fn key_eq_test() {
    let x = Key::new(&[3; 16]);
    let y = Key::new(&[2; 16]);
    let z = [3; 16];
    let u = [3; 17];
    let n = vec![3; 16];

    assert!(x != y);
    assert_eq!(x, z);
    assert_eq!(n, z);
    assert!(x != n); // NOTE Key<[i32; 16]> != Vec<i32>
    assert_eq!(x, *n);
    assert!(x != u);
    assert_eq!(x, Key::new(&z));
    assert!(x != Key::new(&y));
    assert!(x != Key::new(&u));
}
