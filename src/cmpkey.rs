use core::{ fmt, mem };
use core::cmp::{ self, Ordering };
use memsec::{ memeq, memcmp };


/// Constant Time Compare
///
/// # Note
///
/// it compare memory value.
#[repr(transparent)]
pub struct CmpKey<T: AsRef<[u8]>>(pub T);


impl<T: AsRef<[u8]>> CmpKey<T> {
    #[inline]
    pub fn from(t: &T) -> &CmpKey<T> {
        unsafe { &*(t as *const T as *const CmpKey<T>) }
    }
}

impl<T: AsRef<[u8]>> fmt::Debug for CmpKey<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("CmpKey")
            .field(&format_args!("{:p}", self.0.as_ref()))
            .finish()
    }
}

impl<T: AsRef<[u8]>> PartialEq<T> for CmpKey<T> {
    fn eq(&self, rhs: &T) -> bool {
        let x = self.0.as_ref();
        let y = rhs.as_ref();

        let len1 = x.len();
        let len2 = y.len();

        let r = unsafe {
            memeq(x.as_ptr(), y.as_ptr(), cmp::min(len1, len2))
        };

        len1 == len2 && r
    }
}

impl<T: AsRef<[u8]>> PartialEq<CmpKey<T>> for CmpKey<T> {
    #[inline]
    fn eq(&self, &CmpKey(ref rhs): &CmpKey<T>) -> bool {
        self.eq(rhs)
    }
}

impl<T: AsRef<[u8]>> Eq for CmpKey<T> {}

impl<T: AsRef<[u8]>> PartialOrd<T> for CmpKey<T> {
    #[inline]
    fn partial_cmp(&self, rhs: &T) -> Option<Ordering> {
        self.partial_cmp(CmpKey::from(rhs))
    }
}

impl<T: AsRef<[u8]>> PartialOrd<CmpKey<T>> for CmpKey<T> {
    #[inline]
    fn partial_cmp(&self, rhs: &CmpKey<T>) -> Option<Ordering> {
        Some(self.cmp(rhs))
    }
}

impl<T: AsRef<[u8]>> Ord for CmpKey<T> {
    fn cmp(&self, &CmpKey(ref rhs): &CmpKey<T>) -> Ordering {
        let x = self.0.as_ref();
        let y = rhs.as_ref();

        let len1 = x.len();
        let len2 = y.len();

        let order = unsafe {
            memcmp(x.as_ptr(), y.as_ptr(), cmp::min(len1, len2))
        };

        let r = len1.cmp(&len2);
        match order.cmp(&0) {
            Ordering::Equal => r,
            order => order
        }
    }
}
