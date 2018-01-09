use core::{ fmt, mem };
use core::cmp::Ordering;
use core::ops::{ Deref, DerefMut };
use memsec::{ memeq, memcmp, memzero };
#[cfg(feature = "use_std")] use memsec::{ mlock, munlock };


/// Temporary Key.
///
/// ```
/// use seckey::TempKey;
///
/// let mut key = [8u8; 8];
/// let key = TempKey::new(&mut key);
/// assert_eq!(key, [8u8; 8]);
/// assert_ne!(key, [1u8; 8]);
/// let mut key2 = [8u8; 8];
/// assert_eq!(key, TempKey::new(&mut key2));
/// ```
pub struct TempKey<'a, T: Sized + 'a>(&'a mut T);

pub struct NeedsDrop;

// TODO use TryFrom
// :( https://github.com/rust-lang/rust/issues/33417#issuecomment-347046063
impl<'a, T> TempKey<'a, T> where T: Sized + 'a {
    pub fn try_from(t: &'a mut T) -> Result<TempKey<'a, T>, NeedsDrop> {
        if mem::needs_drop::<T>() {
            Err(NeedsDrop)
        } else {
            #[cfg(feature = "use_std")]
            unsafe { mlock(t, mem::size_of::<T>()) };

            Ok(TempKey(t))
        }
    }
}

impl<'a, T> TempKey<'a, T> where T: Sized + Copy + 'a {
    pub fn new(t: &'a mut T) -> TempKey<'a, T> {
        #[cfg(feature = "use_std")]
        unsafe { mlock(t, mem::size_of::<T>()) };

        TempKey(t)
    }
}


impl<'a, T> Deref for TempKey<'a, T> where T: Sized + 'a {
    type Target = T;

    fn deref(&self) -> &T {
        self.0
    }
}


impl<'a, T> DerefMut for TempKey<'a, T> where T: Sized + 'a {
    fn deref_mut(&mut self) -> &mut T {
        self.0
    }
}

impl<'a, T> fmt::Debug for TempKey<'a, T> where T: Sized + 'a {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("TempKey")
            .field(&format_args!("{:p}", self.0))
            .finish()
    }
}

impl<'a, T> PartialEq<T> for TempKey<'a, T> where T: Sized + 'a {
    /// Constant time eq.
    ///
    /// NOTE, it compare memory value.
    fn eq(&self, rhs: &T) -> bool {
        unsafe { memeq(self.0, rhs, mem::size_of::<T>()) }
    }
}

impl<'a, 'b, T> PartialEq<TempKey<'b, T>> for TempKey<'a, T> where T: Sized + 'a {
    /// Constant time eq.
    ///
    /// NOTE, it compare memory value.
    #[inline]
    fn eq(&self, rhs: &TempKey<T>) -> bool {
        self.eq(rhs as &T)
    }
}

impl<'a, T> Eq for TempKey<'a, T> where T: Sized + 'a {}

impl<'a, T> PartialOrd<T> for TempKey<'a, T> where T: Sized + 'a {
    /// Constant time cmp.
    ///
    /// NOTE, it compare memory value.
    fn partial_cmp(&self, rhs: &T) -> Option<Ordering> {
        let order =
            unsafe { memcmp(self.0, rhs, mem::size_of::<T>()) };
        Some(order.cmp(&0))
    }
}

impl<'a, 'b, T> PartialOrd<TempKey<'b, T>> for TempKey<'a, T> where T: Sized + 'a {
    #[inline]
    fn partial_cmp(&self, rhs: &TempKey<T>) -> Option<Ordering> {
        self.partial_cmp(rhs as &T)
    }
}

impl<'a, T> Ord for TempKey<'a, T> where T: Sized + 'a {
    #[inline]
    fn cmp(&self, rhs: &TempKey<T>) -> Ordering {
        self.partial_cmp(rhs).unwrap()
    }
}

impl<'a, T> Drop for TempKey<'a, T> where T: Sized {
    fn drop(&mut self) {
        #[cfg(feature = "use_std")]
        unsafe { munlock(self.0, mem::size_of::<T>()) };

        unsafe { memzero(self.0, mem::size_of::<T>()) };
    }
}
