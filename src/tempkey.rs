use core::fmt;
use core::ops::{ Deref, DerefMut };

#[cfg(not(feature = "use_os"))]
use memsec::memzero;

#[cfg(feature = "use_os")]
use memsec::{ mlock, munlock };


/// Temporary Key
///
/// ```
/// use seckey::{ TempKey, CmpKey };
///
/// let mut key = [8u8; 8];
/// let key = TempKey::new(&mut key);
/// assert_eq!(CmpKey(&key[..]), &[8u8; 8][..]);
/// ```
///
/// # Note
///
/// * It will zero the value when `Drop`.
/// * It will refuse to accept if `T` is reference or pointer, to avoid causing null pointer.
/// * It is a reference, to avoid it from being affected by stack copy (return value).
#[repr(transparent)]
pub struct TempKey<T: AsMut<[u8]>>(T);


impl<T: AsMut<[u8]>> TempKey<T> {
    #[allow(unused_mut)]
    pub fn new(mut t: T) -> TempKey<T> {
        #[cfg(feature = "use_os")]
        unsafe {
            let t = t.as_mut();
            mlock(t.as_mut_ptr(), t.len());
        }

        TempKey(t)
    }
}

impl<T: AsMut<[u8]>> Deref for TempKey<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: AsMut<[u8]>> DerefMut for TempKey<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: AsMut<[u8]>> fmt::Debug for TempKey<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("TempKey")
            .field(&format_args!("{:p}", &self.0))
            .finish()
    }
}

impl<T: AsMut<[u8]>> Drop for TempKey<T> {
    fn drop(&mut self) {
        unsafe {
            let t = self.0.as_mut();
            let size = t.len();

            #[cfg(feature = "use_os")]
            munlock(t.as_mut_ptr(), size);

            #[cfg(not(feature = "use_os"))]
            memzero(t.as_mut_ptr(), size);
        }
    }
}
