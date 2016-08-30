#![feature(test)]

extern crate test;
extern crate seckey;

use test::Bencher;
use seckey::Key;


#[bench]
fn key_eq_bench(b: &mut Bencher) {
    let x = Key::new([9; 4096]);
    let y = Key::new([9; 4096]);

    b.iter(|| x == y);
}

#[bench]
fn key_nq_bench(b: &mut Bencher) {
    let x = Key::new([8; 4096]);
    let z = Key::new([3; 4096]);

    b.iter(|| x == z);
}
