# seckey
[![travis-ci](https://travis-ci.org/quininer/seckey.svg?branch=master)](https://travis-ci.org/quininer/seckey)
[![appveyor](https://ci.appveyor.com/api/projects/status/fcldrw36r359us9i?svg=true)](https://ci.appveyor.com/project/quininer/seckey)
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
