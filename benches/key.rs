#![feature(test)]

extern crate test;
extern crate seckey;

use test::Bencher;
use seckey::Key;


#[bench]
fn key_eq_bench(b: &mut Bencher) {
    let x = Key::new(&[9i32; 4096]);
    let y = [9i32; 4096];

    b.iter(|| x == y);
}

#[bench]
fn key_nq_bench(b: &mut Bencher) {
    let x = Key::new(&[8i32; 4096]);
    let z = [3i32; 4096];

    b.iter(|| x == z);
}
