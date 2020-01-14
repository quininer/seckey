use core::{ fmt, mem, str };
use core::ptr::{ self, NonNull };
use core::ops::{ Deref, DerefMut };
use core::cell::Cell;
use memsec::{ memzero, memset, malloc, malloc_sized, free, mprotect, Prot };


/// Secure Key
///
/// The use [memsec/malloc](../../memsec/fn.malloc.html) protection secret bytes.
///
/// Note that this does not protect data outside of the secure heap.
///
/// More docs see [Secure memory · libsodium](https://download.libsodium.org/doc/helpers/memory_management.html).
pub struct SecKey<T: ?Sized> {
    ptr: NonNull<T>,
    count: Cell<usize>
}

impl<T> SecKey<T> {
    /// ```
    /// use seckey::{ free, SecKey };
    ///
    /// let k = SecKey::new([1, 2, 3])
    ///     .unwrap_or_else(|mut val| {
    ///         // NOTE should zero it
    ///         free(val);
    ///         panic!()
    ///     });
    /// assert_eq!([1, 2, 3], *k.read());
    /// ```
    pub fn new(mut t: T) -> Result<SecKey<T>, T> {
        unsafe {
            match Self::from_ptr(&t) {
                Some(output) => {
                    memzero(&mut t as *mut T as *mut u8, mem::size_of::<T>());
                    mem::forget(t);
                    Ok(output)
                },
                None => Err(t)
            }
        }
    }

    /// ```
    /// use seckey::SecKey;
    ///
    /// let mut v = [1, 2, 3];
    /// let k = unsafe { SecKey::from_ptr(&v).unwrap() };
    /// assert_eq!([1, 2, 3], v);
    /// assert_eq!([1, 2, 3], *k.read());
    /// ```
    #[inline]
    pub unsafe fn from_ptr(t: *const T) -> Option<SecKey<T>> {
        Self::with(move |memptr| ptr::copy_nonoverlapping(t, memptr, 1))
    }

    /// ```
    /// use seckey::SecKey;
    ///
    /// let k: SecKey<u32> = unsafe { SecKey::with(|ptr| *ptr = 1).unwrap() };
    /// assert_eq!(1, *k.read());
    /// ```
    pub unsafe fn with<F>(f: F) -> Option<SecKey<T>>
        where F: FnOnce(*mut T)
    {
        let memptr = malloc()?;

        f(memptr.as_ptr());
        mprotect(memptr, Prot::NoAccess);

        Some(SecKey {
            ptr: memptr,
            count: Cell::new(0)
        })
    }
}

impl<T: Copy> SecKey<T> {
    pub fn from_ref(t: &T) -> Option<SecKey<T>> {
        unsafe { Self::from_ptr(t) }
    }
}

impl<T: Default> SecKey<T> {
    /// ```
    /// use seckey::SecKey;
    ///
    /// let k: SecKey<u32> = SecKey::with_default(|ptr| *ptr += 1).unwrap();
    /// assert_eq!(1, *k.read());
    /// ```
    pub fn with_default<F>(f: F) -> Option<SecKey<T>>
        where F: FnOnce(&mut T)
    {
        unsafe {
            Self::with(|p| {
                ptr::write(p, T::default());
                f(&mut *p);
            })
        }
    }
}

impl SecKey<[u8]> {
    /// On success `src` is zeroed and a new protected `SecKey<[u8]>` is returned.
    /// On failure `src` remains untouched and `None` is returned.
    ///
    /// ```
    /// use seckey::SecKey;
    ///
    /// let mut unprotected = [1u8; 2];
    /// let k = SecKey::from_bytes(&mut unprotected[..]).unwrap();
    ///
    /// assert_eq!(unprotected, [0u8; 2]);
    /// assert_eq!(*k.read(), [1u8; 2]);
    /// ```
    pub fn from_bytes(src: &mut [u8]) -> Option<SecKey<[u8]>> {
        unsafe {
            let mut memptr = malloc_sized(src.len())?;

            // copy secret from source
            ptr::copy_nonoverlapping(
                src.as_ptr(),
                memptr.as_mut().as_mut_ptr(),
                src.len()
            );

            // protect secret
            mprotect(memptr, Prot::NoAccess);

            // zero original source
            memzero(src.as_mut_ptr(), src.len());

            Some(SecKey {
                ptr: memptr,
                count: Cell::new(0),
            })
        }
    }

    pub fn with_len(val: u8, len: usize) -> Option<SecKey<[u8]>> {
        unsafe {
            let mut memptr = malloc_sized(len)?;

            // initialize
            memset(memptr.as_mut().as_mut_ptr(), val, len);

            // protect secret
            mprotect(memptr, Prot::NoAccess);

            Some(SecKey {
                ptr: memptr,
                count: Cell::new(0),
            })
        }
    }
}

impl SecKey<str> {
    /// On success `src` is zeroed and a new protected `SecKey<str>` is returned.
    /// On failure `src` remains untouched and `None` is returned.
    ///
    /// ```
    /// use seckey::SecKey;
    ///
    /// let mut unprotected = "abc".to_string();
    /// let k = SecKey::from_str(&mut unprotected).unwrap();
    ///
    /// assert_eq!(&unprotected, "\0\0\0");
    /// assert_eq!(&*k.read(), "abc");
    /// ```
    pub fn from_str(src: &mut str) -> Option<SecKey<str>> {
        unsafe {
            let src = src.as_bytes_mut();
            let mut memptr = malloc_sized(src.len())?;

            // copy secret from source
            ptr::copy_nonoverlapping(
                src.as_ptr(),
                memptr.as_mut().as_mut_ptr(),
                src.len()
            );
            let strptr = NonNull::new_unchecked(
                str::from_utf8_unchecked_mut(memptr.as_mut()) as *mut str
            );

            // protect secret
            mprotect(strptr, Prot::NoAccess);

            // zero original source
            memzero(src.as_mut_ptr(), src.len());

            Some(SecKey {
                ptr: strptr,
                count: Cell::new(0),
            })
        }
    }
}

impl<T: ?Sized> SecKey<T> {
    #[inline]
    unsafe fn lock(&self) {
        let count = self.count.get();
        self.count.set(count - 1);
        if count <= 1 {
            mprotect(self.ptr, Prot::NoAccess);
        }
    }

    /// Borrow Read
    ///
    /// ```
    /// use seckey::SecKey;
    ///
    /// let secpass = SecKey::new([8u8; 8]).unwrap();
    /// assert_eq!([8u8; 8], *secpass.read());
    /// ```
    #[inline]
    pub fn read(&self) -> SecReadGuard<T> {
        let count = self.count.get();
        self.count.set(count + 1);
        if count == 0 {
            unsafe { mprotect(self.ptr, Prot::ReadOnly) };
        }

        SecReadGuard(self)
    }

    /// Borrow Write
    ///
    /// ```
    /// # use seckey::SecKey;
    /// #
    /// # let mut secpass = SecKey::new([8u8; 8]).unwrap();
    /// let mut wpass = secpass.write();
    /// wpass[0] = 0;
    /// assert_eq!([0, 8, 8, 8, 8, 8, 8, 8], *wpass);
    /// ```
    #[inline]
    pub fn write(&mut self) -> SecWriteGuard<T> {
        let count = self.count.get();
        self.count.set(count + 1);
        if count == 0 {
            unsafe { mprotect(self.ptr, Prot::ReadWrite) };
        }

        SecWriteGuard(self)
    }
}

impl<T: ?Sized> fmt::Debug for SecKey<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("SecKey")
            .field(&format_args!("{:p}", self.ptr))
            .field(&self.count)
            .finish()
    }
}

impl<T: ?Sized> fmt::Pointer for SecKey<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:p}", self.ptr)
    }
}

impl<T: ?Sized> Drop for SecKey<T> {
    fn drop(&mut self) {
        unsafe {
            mprotect(self.ptr, Prot::ReadWrite);
            ptr::drop_in_place(self.ptr.as_ptr());
            free(self.ptr);
        }
    }
}


/// Read Guard
pub struct SecReadGuard<'a, T: 'a + ?Sized>(&'a SecKey<T>);

impl<'a, T: 'a + ?Sized> Deref for SecReadGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { self.0.ptr.as_ref() }
    }
}

impl<'a, T: 'a + ?Sized> Drop for SecReadGuard<'a, T> {
    fn drop(&mut self) {
        unsafe { self.0.lock() }
    }
}


/// Write Guard
pub struct SecWriteGuard<'a, T: 'a + ?Sized>(&'a mut SecKey<T>);

impl<'a, T: 'a + ?Sized> Deref for SecWriteGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { self.0.ptr.as_ref() }
    }
}

impl<'a, T: 'a + ?Sized> DerefMut for SecWriteGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { self.0.ptr.as_mut() }
    }
}

impl<'a, T: 'a + ?Sized> Drop for SecWriteGuard<'a, T> {
    fn drop(&mut self) {
        unsafe { self.0.lock() }
    }
}
