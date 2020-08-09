use core::alloc::{ GlobalAlloc, Layout };
use memsec::memzero;


#[derive(Debug, Clone, Copy, Default)]
pub struct ZeroAllocator<T>(pub T);

unsafe impl<T: GlobalAlloc> GlobalAlloc for ZeroAllocator<T> {
    #[inline(always)]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.0.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        memzero(ptr, layout.size());
        self.0.dealloc(ptr, layout)
    }

    #[inline(always)]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        self.0.alloc_zeroed(layout)
    }

    #[inline(always)]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        self.0.realloc(ptr, layout, new_size)
    }
}
