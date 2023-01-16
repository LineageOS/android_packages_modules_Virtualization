use crate::memory::{alloc_shared, dealloc_shared, virt_to_phys};
use core::ptr::{copy_nonoverlapping, NonNull};
use log::debug;
use virtio_drivers::{BufferDirection, Hal, PhysAddr, VirtAddr, PAGE_SIZE};

pub struct HalImpl;

impl Hal for HalImpl {
    fn dma_alloc(pages: usize) -> PhysAddr {
        debug!("dma_alloc: pages={}", pages);
        let size = pages * PAGE_SIZE;
        let vaddr = alloc_shared(size)
            .expect("Failed to allocate and share VirtIO DMA range with host")
            .as_ptr() as VirtAddr;
        virt_to_phys(vaddr)
    }

    fn dma_dealloc(paddr: PhysAddr, pages: usize) -> i32 {
        debug!("dma_dealloc: paddr={:#x}, pages={}", paddr, pages);
        let vaddr = Self::phys_to_virt(paddr);
        let size = pages * PAGE_SIZE;
        // Safe because the memory was allocated by `dma_alloc` above using the same allocator, and
        // the layout is the same as was used then.
        unsafe {
            dealloc_shared(vaddr, size).expect("Failed to unshare VirtIO DMA range with host");
        }
        0
    }

    fn phys_to_virt(paddr: PhysAddr) -> VirtAddr {
        paddr
    }

    fn share(buffer: NonNull<[u8]>, direction: BufferDirection) -> PhysAddr {
        let size = buffer.len();

        // TODO: Copy to a pre-shared region rather than allocating and sharing each time.
        // Allocate a range of pages, copy the buffer if necessary, and share the new range instead.
        let copy =
            alloc_shared(size).expect("Failed to allocate and share VirtIO buffer with host");
        if direction == BufferDirection::DriverToDevice {
            unsafe {
                copy_nonoverlapping(buffer.as_ptr() as *mut u8, copy.as_ptr(), size);
            }
        }
        virt_to_phys(copy.as_ptr() as VirtAddr)
    }

    fn unshare(paddr: PhysAddr, buffer: NonNull<[u8]>, direction: BufferDirection) {
        let vaddr = Self::phys_to_virt(paddr);
        let size = buffer.len();
        if direction == BufferDirection::DeviceToDriver {
            debug!(
                "Copying VirtIO buffer back from {:#x} to {:#x}.",
                paddr,
                buffer.as_ptr() as *mut u8 as usize
            );
            unsafe {
                copy_nonoverlapping(vaddr as *const u8, buffer.as_ptr() as *mut u8, size);
            }
        }

        // Unshare and deallocate the shared copy of the buffer.
        debug!("Unsharing VirtIO buffer {:#x}", paddr);
        // Safe because the memory was allocated by `share` using `alloc_shared`, and the size is
        // the same as was used then.
        unsafe {
            dealloc_shared(vaddr, size).expect("Failed to unshare VirtIO buffer with host");
        }
    }
}
