use core::fmt;
use core::ops::{ Deref, DerefMut };

#[cfg(not(feature = "ues_os"))]
use memsec::memzero;

#[cfg(feature = "use_os")]
use memsec::{ mlock, munlock };


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
pub struct TempKey<'a, T: AsMut<[u8]>>(&'a mut T);


impl<'a, T: AsMut<[u8]>> TempKey<'a, T> {
    pub fn new(t: &'a mut T) -> TempKey<'a, T> {
        #[cfg(feature = "use_os")] unsafe {
            let t = t.as_mut();
            mlock(t.as_mut_ptr(), t.len());
        }

        TempKey(t)
    }
}

impl<'a, T: AsMut<[u8]>> Deref for TempKey<'a, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        self.0
    }
}

impl<'a, T: AsMut<[u8]>> DerefMut for TempKey<'a, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        self.0
    }
}

impl<'a, T: AsMut<[u8]>> fmt::Debug for TempKey<'a, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("TempKey")
            .field(&format_args!("{:p}", &self.0))
            .finish()
    }
}

impl<'a, T: AsMut<[u8]>> Drop for TempKey<'a, T> {
    fn drop(&mut self) {
        unsafe {
            let t = self.0.as_mut();
            let size = t.len();

            #[cfg(feature = "ues_os")]
            munlock(t.as_mut_ptr(), size);

            #[cfg(not(feature = "ues_os"))]
            memzero(t.as_mut_ptr(), size);
        }
    }
}
