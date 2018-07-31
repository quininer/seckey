use core::{ fmt, mem, ptr };
use core::ops::{ Deref, DerefMut };
#[cfg(not(feature = "use_std"))] use memsec::memzero;
#[cfg(feature = "use_std")] use memsec::{ mlock, munlock };


/// Temporary Key
///
/// ```
/// use seckey::{ TempKey, CmpKey };
///
/// let mut key = [8u8; 8];
/// let key = TempKey::from(&mut key);
/// assert_eq!(CmpKey::from(&*key), &[8u8; 8]);
/// ```
///
/// # Note
///
/// * It will zero the value when `Drop`.
/// * It will refuse to accept if `T` is reference or pointer, to avoid causing null pointer.
/// * It is a reference, to avoid it from being affected by stack copy (return value).
pub struct TempKey<'a, T: ?Sized + 'static>(&'a mut T);


impl<'a, T: ?Sized> From<&'a mut T> for TempKey<'a, T> {
    fn from(t: &'a mut T) -> TempKey<'a, T> {
        #[cfg(feature = "use_std")] unsafe {
            mlock(t as *mut T as *mut u8, mem::size_of_val(t));
        }

        TempKey(t)
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

impl<'a, T: ?Sized> Drop for TempKey<'a, T> {
    fn drop(&mut self) {
        let size = mem::size_of_val(self.0);

        unsafe {
            ptr::drop_in_place(&mut self.0);

            #[cfg(feature = "use_std")]
            munlock(self.0 as *mut T as *mut u8, size);

            #[cfg(not(feature = "use_std"))]
            memzero(self.0 as *mut T as *mut u8, size);
        }
    }
}
