use core::{ fmt, mem };
use core::cmp::{ self, Ordering };
use core::ops::{ Deref, DerefMut };
use memsec::{ memeq, memcmp };
#[cfg(not(feature = "use_std"))] use memsec::memzero;
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
///
/// let mut key2 = [8u8; 8];
/// assert_eq!(key, *TempKey::new(&mut key2));
/// ```
pub struct TempKey<'a, T: ?Sized + 'a>(&'a mut T);

pub struct NeedsDrop;


impl<'a, T: ?Sized + Copy> TempKey<'a, T> {
    pub fn new(t: &'a mut T) -> TempKey<'a, T> {
        #[cfg(feature = "use_std")]
        unsafe { mlock(t as *mut T as *mut u8, mem::size_of_val(t)) };

        TempKey(t)
    }
}

// TODO use TryFrom
// :( https://github.com/rust-lang/rust/issues/33417#issuecomment-347046063
impl<'a, T: Sized> TempKey<'a, T> {
    pub fn try_from(t: &'a mut T) -> Result<TempKey<'a, T>, NeedsDrop> {
        if mem::needs_drop::<T>() {
            Err(NeedsDrop)
        } else {
            #[cfg(feature = "use_std")]
            unsafe { mlock(t, mem::size_of_val(t)) };

            Ok(TempKey(t))
        }
    }
}

impl<'a, T: Sized + Copy> TempKey<'a, [T]> {
    pub fn from_slice(t: &'a mut [T]) -> TempKey<'a, [T]> {
        #[cfg(feature = "use_std")]
        unsafe { mlock(t.as_mut_ptr() as *mut u8, mem::size_of_val(t)) };

        TempKey(t)
    }
}

impl<'a, T: Sized> TempKey<'a, [T]> {
    pub fn try_from_slice(t: &'a mut [T]) -> Result<TempKey<'a, [T]>, NeedsDrop> {
        if mem::needs_drop::<T>() {
            Err(NeedsDrop)
        } else {
            #[cfg(feature = "use_std")]
            unsafe { mlock(t.as_mut_ptr() as *mut u8, mem::size_of_val(t)) };

            Ok(TempKey(t))
        }
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
    /// Constant time eq.
    ///
    /// NOTE, it compare memory value.
    fn eq(&self, rhs: &T) -> bool {
        let len1 = mem::size_of_val(self.0);
        let len2 = mem::size_of_val(rhs);

        let r = unsafe { memeq(
            self.0 as *const T as *const u8,
            rhs as *const T as *const u8,
            len1
        ) };
        len1 == len2 && r
    }
}

impl<'a, 'b, T: Sized> PartialEq<TempKey<'b, T>> for TempKey<'a, T> {
    /// Constant time eq.
    ///
    /// NOTE, it compare memory value.
    fn eq(&self, rhs: &TempKey<T>) -> bool {
        self.eq(rhs.deref())
    }
}

impl<'a, T: Sized> Eq for TempKey<'a, T> {}

impl<'a, T: ?Sized> PartialOrd<T> for TempKey<'a, T> {
    /// Constant time cmp.
    ///
    /// NOTE, it compare memory value.
    fn partial_cmp(&self, rhs: &T) -> Option<Ordering> {
        let len1 = mem::size_of_val(self.0);
        let len2 = mem::size_of_val(rhs);

        let order = unsafe { memcmp(
            self.0 as *const T as *const u8,
            rhs as *const T as *const u8,
            cmp::min(len1, len2))
        };

        Some(match order.cmp(&0) {
            Ordering::Equal => len1.cmp(&len2),
            order => order
        })
    }
}

impl<'a, 'b, T: Sized> PartialOrd<TempKey<'b, T>> for TempKey<'a, T> {
    fn partial_cmp(&self, rhs: &TempKey<T>) -> Option<Ordering> {
        self.partial_cmp(rhs.deref())
    }
}

impl<'a, T: Sized> Ord for TempKey<'a, T> {
    fn cmp(&self, rhs: &TempKey<T>) -> Ordering {
        self.partial_cmp(rhs).unwrap()
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
