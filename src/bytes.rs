use std::fmt;
use std::cmp::{ Ordering, min };
use std::iter::repeat;
use std::ops::{ Deref, DerefMut };
use memsec::{ memeq, memcmp, mlock, munlock };


/// Temporary Bytes.
///
/// ```
/// use seckey::Bytes;
///
/// let bytes = Bytes::new(&[8; 8]);
///
/// assert_eq!(bytes, [8; 8]);
/// ```
#[derive(Default)]
pub struct Bytes(Vec<u8>);

impl Bytes {
    /// Create a new Bytes.
    #[inline]
    pub fn new(input: &[u8]) -> Bytes {
        Bytes::from(Vec::from(input))
    }

    /// Create a empty Bytes.
    #[inline]
    pub fn empty() -> Bytes {
        Self::default()
    }
}

impl From<Vec<u8>> for Bytes {
    #[inline]
    fn from(mut t: Vec<u8>) -> Bytes {
        unsafe { mlock(t.as_mut_ptr(), t.len()) };
        Bytes(t)
    }
}

impl<'a> From<&'a [u8]> for Bytes {
    #[inline]
    fn from(t: &'a [u8]) -> Bytes {
        Bytes::new(t)
    }
}

impl Deref for Bytes {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl DerefMut for Bytes {
    #[inline]
    fn deref_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl Clone for Bytes {
    fn clone(&self) -> Bytes {
        Bytes::from(self.0.clone())
    }
}

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut fmt = f.debug_tuple("Bytes");
        match self.len() {
            0 => fmt.finish(),
            len @ 1...32 => fmt
                .field(&repeat('*').take(len).collect::<String>())
                .finish(),
            len => fmt.field(&len).finish()
        }
    }
}

impl AsRef<[u8]> for Bytes {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}

impl<A: AsRef<[u8]>> PartialEq<A> for Bytes {
    #[inline]
    fn eq(&self, rhs: &A) -> bool {
        self.eq(rhs.as_ref())
    }
}

impl PartialEq<[u8]> for Bytes {
    /// Constant time eq.
    fn eq(&self, rhs: &[u8]) -> bool {
        let minlen = min(self.len(), rhs.len());
        let output =
            unsafe { memeq(self.as_ptr(), rhs.as_ptr(), minlen) };

        self.len() == rhs.len() && output
    }
}

impl Eq for Bytes {}

impl<A: AsRef<[u8]>> PartialOrd<A> for Bytes {
    #[inline]
    fn partial_cmp(&self, rhs: &A) -> Option<Ordering> {
        self.partial_cmp(rhs.as_ref())
    }
}

impl PartialOrd<[u8]> for Bytes {
    /// Constant time cmp.
    fn partial_cmp(&self, rhs: &[u8]) -> Option<Ordering> {
        let minlen = min(self.len(), rhs.len());
        let order =
            unsafe { memcmp(self.as_ptr(), rhs.as_ptr(), minlen) };
        if order == 0 {
            Some(self.len().cmp(&rhs.len()))
        } else if order < 0 {
            Some(Ordering::Less)
        } else {
            Some(Ordering::Greater)
        }
    }
}

impl Ord for Bytes {
    #[inline]
    fn cmp(&self, rhs: &Bytes) -> Ordering {
        self.partial_cmp(rhs.as_ref()).unwrap()
    }
}

impl Drop for Bytes {
    fn drop(&mut self) {
        unsafe { munlock(self.0.as_mut_ptr(), self.0.len()) };
    }
}
