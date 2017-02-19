# seckey
[![crates](https://img.shields.io/crates/v/seckey.svg)](https://crates.io/crates/seckey)
[![license](https://img.shields.io/github/license/quininer/seckey.svg)](https://github.com/quininer/seckey/blob/master/LICENSE)
[![docs.rs](https://docs.rs/seckey/badge.svg)](https://docs.rs/seckey/)

Use [memsec](https://github.com/quininer/memsec) protected secret memory.

### exmaple

```rust
use seckey::SecKey;

let secpass = SecKey::new([8u8; 8]).unwrap();

{
	assert_eq!([8u8; 8], *secpass.read());
}

{
	let mut wpass = secpass.write();
	wpass[0] = 0;
	assert_eq!([0, 8, 8, 8, 8, 8, 8, 8], *wpass);
}
```

or `placement syntax`

```rust
#![feature(placement_in_syntax)]

use seckey::SecHeap;

let k = SecHeap <- [1];
assert_eq!([1], *k.read());
```
