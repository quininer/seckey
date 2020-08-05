use core::fmt;
use core::ptr::NonNull;
use core::ops::{ Deref, DerefMut };

#[cfg(feature = "use_os")]
use core::cell::Cell;

#[cfg(feature = "use_os")]
use memsec::{ mprotect, Prot };


#[cfg(feature = "use_os")]
mod alloc {
    use std::ptr::NonNull;

    #[inline]
    pub unsafe fn malloc_sized(size: usize) -> Option<NonNull<u8>> {
        let memptr = memsec::malloc_sized(size)?;
        Some(memptr.cast())
    }

    pub unsafe fn free(memptr: NonNull<u8>, _size: usize) {
        memsec::free(memptr);
    }
}

#[cfg(not(feature = "use_os"))]
mod alloc {
    use std::ptr::NonNull;
    use std::alloc::Layout;

    #[inline]
    pub unsafe fn malloc_sized(size: usize) -> Option<NonNull<u8>> {
        NonNull::new(std::alloc::alloc(Layout::from_size_align_unchecked(size, 1)))
    }

    #[inline]
    pub unsafe fn free(memptr: NonNull<u8>, size: usize) {
        std::alloc::dealloc(memptr.as_ptr(), Layout::from_size_align_unchecked(size, 1));
    }
}

pub struct SecBytes {
    ptr: NonNull<u8>,
    len: usize,

    #[cfg(feature = "use_os")]
    count: Cell<usize>
}

// Safety: It is safe to make SecBytes sendable because `ptr` is only used
//         by us and it doesn't have any thread specific behavior.
unsafe impl Send for SecBytes {}

impl SecBytes {
    pub fn new(len: usize) -> SecBytes {
        fn id(_: &mut [u8]) {}

        SecBytes::with(len, id)
    }

    pub fn with<F>(len: usize, f: F) -> SecBytes
        where F: FnOnce(&mut [u8])
    {
        let ptr = unsafe {
            let memptr = alloc::malloc_sized(len).expect("seckey alloc failed");

            {
                let arr = std::slice::from_raw_parts_mut(memptr.as_ptr(), len);
                f(arr);
            }

            #[cfg(feature = "use_os")]
            mprotect(memptr, Prot::NoAccess);

            memptr
        };

        SecBytes {
            ptr, len,

            #[cfg(feature = "use_os")]
            count: Cell::new(0)
        }
    }

    /// Borrow Read
    ///
    /// ```
    /// use seckey::SecBytes;
    ///
    /// let secpass = SecBytes::with(8, |buf| buf.copy_from_slice(&[8u8; 8][..]));
    /// assert_eq!([8u8; 8], *secpass.read());
    /// ```
    #[cfg_attr(not(feature = "use_os"), inline)]
    pub fn read(&self) -> SecReadGuard<'_> {
        #[cfg(feature = "use_os")] {
            let count = self.count.get();
            self.count.set(count + 1);
            if count == 0 {
                unsafe { mprotect(self.ptr, Prot::ReadOnly) };
            }
        }

        SecReadGuard(self)
    }

    /// Borrow Write
    ///
    /// ```
    /// # use seckey::SecBytes;
    /// #
    /// # let mut secpass = SecBytes::with(8, |buf| buf.copy_from_slice(&[8u8; 8][..]));
    /// let mut wpass = secpass.write();
    /// wpass[0] = 0;
    /// assert_eq!([0, 8, 8, 8, 8, 8, 8, 8], *wpass);
    /// ```
    #[cfg_attr(not(feature = "use_os"), inline)]
    pub fn write(&mut self) -> SecWriteGuard<'_> {
        #[cfg(feature = "use_os")]
        unsafe {
            mprotect(self.ptr, Prot::ReadWrite)
        };

        SecWriteGuard(self)
    }
}

impl fmt::Debug for SecBytes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("SecBytes")
            .field(&format_args!("{:p}", self.ptr))
            .finish()
    }
}

impl fmt::Pointer for SecBytes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:p}", self.ptr)
    }
}

impl Drop for SecBytes {
    fn drop(&mut self) {
        unsafe {
            #[cfg(feature = "use_os")]
            mprotect(self.ptr, Prot::ReadWrite);

            alloc::free(self.ptr, self.len);
        }
    }
}


/// Read Guard
pub struct SecReadGuard<'a>(&'a SecBytes);

impl<'a> Deref for SecReadGuard<'a> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self.0.ptr.as_ptr(), self.0.len)
        }
    }
}

impl<'a> Drop for SecReadGuard<'a> {
    fn drop(&mut self) {
        #[cfg(feature = "use_os")]
        unsafe {
            let count = self.0.count.get();
            self.0.count.set(count - 1);
            if count <= 1 {
                mprotect(self.0.ptr, Prot::NoAccess);
            }
        }
    }
}


/// Write Guard
pub struct SecWriteGuard<'a>(&'a mut SecBytes);

impl<'a> Deref for SecWriteGuard<'a> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(self.0.ptr.as_ptr(), self.0.len)
        }
    }
}

impl<'a> DerefMut for SecWriteGuard<'a> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe {
            std::slice::from_raw_parts_mut(self.0.ptr.as_ptr(), self.0.len)
        }
    }
}

impl<'a> Drop for SecWriteGuard<'a> {
    fn drop(&mut self) {
        #[cfg(feature = "use_os")]
        unsafe {
            mprotect(self.0.ptr, Prot::NoAccess);
        }
    }
}
