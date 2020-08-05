#![feature(test)]

extern crate test;

use test::{ Bencher, black_box };
use seckey::{ zero, free };


#[bench]
fn test_zero_bytes(b: &mut Bencher) {
    b.iter(|| {
        let mut a = black_box([0x42; 1024]);
        zero(&mut a);
    });
}

#[bench]
fn test_free_bytes(b: &mut Bencher) {
    b.iter(|| {
        let a = black_box([0x42; 1024]);
        free(a);
    });
}
