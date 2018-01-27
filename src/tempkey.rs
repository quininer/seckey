use core::{ fmt, mem };
use core::cmp::{ self, Ordering };
use core::ops::{ Deref, DerefMut };
use memsec::{ memeq, memcmp };
#[cfg(not(feature = "use_std"))] use memsec::memzero;
#[cfg(feature = "use_std")] use memsec::{ mlock, munlock };
use ::ZeroSafe;


/// Temporary Key
///
/// ```
/// use seckey::TempKey;
///
/// let mut key = [8u8; 8];
/// let key = TempKey::from(&mut key);
/// assert_eq!(key, [8u8; 8]);
/// assert_ne!(key, [1u8; 8]);
/// ```
///
/// # Note
///
/// * It will zero the value when `Drop`.
/// * It will refuse to accept if `T` is reference or pointer, to avoid causing null pointer.
/// * It is a reference, to avoid it from being affected by stack copy (return value).
pub struct TempKey<'a, T: ?Sized + 'static>(&'a mut T);


impl<'a, T: ?Sized> TempKey<'a, T> {
    pub unsafe fn unsafe_from(t: &'a mut T) -> TempKey<'a, T> {
        #[cfg(feature = "use_std")]
        mlock(t as *mut T as *mut u8, mem::size_of_val(t));

        TempKey(t)
    }
}

impl<'a, T: ?Sized + ZeroSafe> From<&'a mut T> for TempKey<'a, T> {
    fn from(t: &'a mut T) -> TempKey<'a, T> {
        unsafe { TempKey::unsafe_from(t) }
    }
}

impl<'a, T: ?Sized> Deref for TempKey<'a, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.0
    }
}

impl<'a, T: ?Sized> DerefMut for TempKey<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.0
    }
}

impl<'a, T: ?Sized> fmt::Debug for TempKey<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("TempKey")
            .field(&format_args!("{:p}", self.0))
            .finish()
    }
}

impl<'a, T: ?Sized> PartialEq<T> for TempKey<'a, T> {
    /// Constant time eq
    ///
    /// **NOTE**: it compare memory value.
    fn eq(&self, rhs: &T) -> bool {
        let len1 = mem::size_of_val(self.0);
        let len2 = mem::size_of_val(rhs);

        let r = unsafe { memeq(
            self.0 as *const T as *const u8,
            rhs as *const T as *const u8,
            cmp::min(len1, len2)
        ) };
        len1 == len2 && r
    }
}

impl<'a, T: ?Sized> PartialOrd<T> for TempKey<'a, T> {
    /// Constant time cmp
    ///
    /// **NOTE**: it compare memory value.
    fn partial_cmp(&self, rhs: &T) -> Option<Ordering> {
        let len1 = mem::size_of_val(self.0);
        let len2 = mem::size_of_val(rhs);

        let order = unsafe { memcmp(
            self.0 as *const T as *const u8,
            rhs as *const T as *const u8,
            cmp::min(len1, len2))
        };

        let r = len1.cmp(&len2);
        Some(match order.cmp(&0) {
            Ordering::Equal => r,
            order => order
        })
    }
}

impl<'a, T: ?Sized> Drop for TempKey<'a, T> {
    fn drop(&mut self) {
        let size = mem::size_of_val(self.0);

        #[cfg(feature = "use_std")]
        unsafe { munlock(self.0 as *mut T as *mut u8, size) };

        #[cfg(not(feature = "use_std"))]
        unsafe { memzero(self.0 as *mut T as *mut u8, size) };
    }
}
