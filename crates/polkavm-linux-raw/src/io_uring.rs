use crate as linux_raw;
use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;

pub struct IoUring {
    submit_head_pointer: *const AtomicU32,
    submit_tail_pointer: *const AtomicU32,
    submit_head: u32,
    submit_tail: u32,
    submit_ring_mask: u32,
    submit_capacity: u32,

    cqes: *const linux_raw::io_uring_cqe,
    completion_head_pointer: *const AtomicU32,
    completion_tail_pointer: *const AtomicU32,
    completion_head: u32,
    completion_tail: u32,
    completion_ring_mask: u32,

    fd: linux_raw::Fd,
    _ring_map: linux_raw::Mmap,
    sqes_map: linux_raw::Mmap,
}

unsafe impl Send for IoUring {}
unsafe impl Sync for IoUring {}

impl IoUring {
    pub fn new(queue_size: u32) -> Result<Self, linux_raw::Error> {
        let mut params = linux_raw::io_uring_params::default();
        let fd = linux_raw::sys_io_uring_setup(queue_size, &mut params)?;
        let sring_size = params.sq_off.array + params.sq_entries * core::mem::size_of::<u32>() as u32;
        let cring_size = params.cq_off.cqes + params.cq_entries * core::mem::size_of::<linux_raw::io_uring_cqe>() as u32;
        let ring_size = core::cmp::max(sring_size, cring_size);
        let ring_map = unsafe {
            linux_raw::Mmap::map(
                core::ptr::null_mut(),
                ring_size as usize,
                linux_raw::PROT_READ | linux_raw::PROT_WRITE,
                linux_raw::MAP_SHARED | linux_raw::MAP_POPULATE,
                Some(fd.borrow()),
                u64::from(linux_raw::IORING_OFF_SQ_RING),
            )?
        };

        let sqes_map = unsafe {
            linux_raw::Mmap::map(
                core::ptr::null_mut(),
                params.sq_entries as usize * core::mem::size_of::<linux_raw::io_uring_sqe>(),
                linux_raw::PROT_READ | linux_raw::PROT_WRITE,
                linux_raw::MAP_SHARED | linux_raw::MAP_POPULATE,
                Some(fd.borrow()),
                u64::from(linux_raw::IORING_OFF_SQES),
            )?
        };

        let submit_head_pointer = unsafe { ring_map.as_ptr().byte_add(params.sq_off.head as usize).cast::<AtomicU32>() };
        let submit_tail_pointer = unsafe { ring_map.as_ptr().byte_add(params.sq_off.tail as usize).cast::<AtomicU32>() };
        let submit_capacity = unsafe { *ring_map.as_ptr().byte_add(params.sq_off.ring_entries as usize).cast::<u32>() };
        let array = unsafe { ring_map.as_mut_ptr().byte_add(params.sq_off.array as usize).cast::<u32>() };
        for index in 0..submit_capacity {
            unsafe { array.add(index as usize).write(index) };
        }

        let completion_head_pointer = unsafe { ring_map.as_ptr().byte_add(params.cq_off.head as usize).cast::<AtomicU32>() };
        let completion_tail_pointer = unsafe { ring_map.as_ptr().byte_add(params.cq_off.tail as usize).cast::<AtomicU32>() };

        Ok(IoUring {
            submit_head_pointer,
            submit_tail_pointer,
            submit_head: unsafe { (*submit_head_pointer).load(Ordering::Acquire) },
            submit_tail: unsafe { submit_tail_pointer.cast::<u32>().read() },
            submit_ring_mask: unsafe { *ring_map.as_ptr().byte_add(params.sq_off.ring_mask as usize).cast::<u32>() },
            submit_capacity,

            cqes: unsafe {
                ring_map
                    .as_ptr()
                    .byte_add(params.cq_off.cqes as usize)
                    .cast::<linux_raw::io_uring_cqe>()
            },
            completion_head_pointer,
            completion_tail_pointer,
            completion_head: unsafe { completion_head_pointer.cast::<u32>().read() },
            completion_tail: unsafe { (*completion_tail_pointer).load(Ordering::Acquire) },
            completion_ring_mask: unsafe { *ring_map.as_ptr().byte_add(params.cq_off.ring_mask as usize).cast::<u32>() },

            fd,
            _ring_map: ring_map,
            sqes_map,
        })
    }

    #[allow(clippy::field_reassign_with_default)]
    pub fn queue_read(&mut self, user_data: u64, fd: linux_raw::FdRef, buffer: *mut u8, length: u32) -> Result<(), linux_raw::Error> {
        if self.queue_length() >= self.queue_capacity() {
            return Err(linux_raw::Error::from("no remaining capacity in the io_uring submission queue"));
        }

        let index = self.submit_tail & self.submit_ring_mask;
        let mut sqe = linux_raw::io_uring_sqe::default();
        sqe.opcode = linux_raw::io_uring_op_IORING_OP_READ as u8;
        sqe.fd = fd.raw();
        sqe.__bindgen_anon_2.addr = buffer as u64;
        sqe.len = length;
        sqe.__bindgen_anon_1.off = u64::MAX;
        sqe.user_data = user_data;
        unsafe {
            self.sqes_map
                .as_mut_ptr()
                .cast::<linux_raw::io_uring_sqe>()
                .add(index as usize)
                .write(sqe)
        };
        self.submit_tail = self.submit_tail.wrapping_add(1);

        Ok(())
    }

    #[allow(clippy::field_reassign_with_default)]
    pub fn queue_timeout(&mut self, user_data: u64, event_count: u32, duration: Duration) -> Result<(), linux_raw::Error> {
        if self.queue_length() >= self.queue_capacity() {
            return Err(linux_raw::Error::from("no remaining capacity in the io_uring submission queue"));
        }

        let index = self.submit_tail & self.submit_ring_mask;
        let mut sqe = linux_raw::io_uring_sqe::default();
        sqe.opcode = linux_raw::io_uring_op_IORING_OP_TIMEOUT as u8;
        sqe.fd = -1;
        let timespec = linux_raw::timespec {
            tv_sec: duration.as_secs() as i64,
            tv_nsec: i64::from(duration.subsec_nanos()),
        };
        sqe.__bindgen_anon_2.addr = core::ptr::addr_of!(timespec) as u64;
        sqe.len = event_count;
        sqe.__bindgen_anon_1.off = 0;
        sqe.user_data = user_data;
        unsafe {
            self.sqes_map
                .as_mut_ptr()
                .cast::<linux_raw::io_uring_sqe>()
                .add(index as usize)
                .write(sqe)
        };
        self.submit_tail = self.submit_tail.wrapping_add(1);

        Ok(())
    }

    // Requires Linux 6.7+.
    #[allow(clippy::field_reassign_with_default)]
    pub fn queue_futex_wait(&mut self, user_data: u64, futex: *const AtomicU32, expected_value: u32) -> Result<(), linux_raw::Error> {
        if self.queue_length() >= self.queue_capacity() {
            return Err(linux_raw::Error::from("no remaining capacity in the io_uring submission queue"));
        }

        let index = self.submit_tail & self.submit_ring_mask;
        let mut sqe = linux_raw::io_uring_sqe::default();
        sqe.opcode = linux_raw::io_uring_op_IORING_OP_FUTEX_WAIT as u8;
        sqe.__bindgen_anon_2.addr = futex as usize as u64;
        sqe.__bindgen_anon_1.addr2 = u64::from(expected_value);
        unsafe { sqe.__bindgen_anon_6.__bindgen_anon_1.as_mut().addr3 = u64::from(linux_raw::FUTEX_BITSET_MATCH_ANY) };
        sqe.user_data = user_data;
        sqe.fd = linux_raw::FUTEX2_SIZE_U32 as i32;
        unsafe {
            self.sqes_map
                .as_mut_ptr()
                .cast::<linux_raw::io_uring_sqe>()
                .add(index as usize)
                .write(sqe)
        };
        self.submit_tail = self.submit_tail.wrapping_add(1);

        Ok(())
    }

    // Requires Linux 6.7+.
    #[allow(clippy::field_reassign_with_default)]
    pub fn queue_futex_wake_one(&mut self, user_data: u64, futex: *const AtomicU32) -> Result<(), linux_raw::Error> {
        if self.queue_length() >= self.queue_capacity() {
            return Err(linux_raw::Error::from("no remaining capacity in the io_uring submission queue"));
        }

        let index = self.submit_tail & self.submit_ring_mask;
        let mut sqe = linux_raw::io_uring_sqe::default();
        sqe.opcode = linux_raw::io_uring_op_IORING_OP_FUTEX_WAKE as u8;
        sqe.__bindgen_anon_2.addr = futex as usize as u64;
        sqe.__bindgen_anon_1.addr2 = 1;
        unsafe { sqe.__bindgen_anon_6.__bindgen_anon_1.as_mut().addr3 = u64::from(linux_raw::FUTEX_BITSET_MATCH_ANY) };
        sqe.user_data = user_data;
        sqe.fd = linux_raw::FUTEX2_SIZE_U32 as i32;
        unsafe {
            self.sqes_map
                .as_mut_ptr()
                .cast::<linux_raw::io_uring_sqe>()
                .add(index as usize)
                .write(sqe)
        };
        self.submit_tail = self.submit_tail.wrapping_add(1);

        Ok(())
    }

    pub fn queue_length(&self) -> usize {
        self.submit_tail.wrapping_sub(self.submit_head) as usize
    }

    pub fn queue_capacity(&self) -> usize {
        self.submit_capacity as usize
    }

    pub unsafe fn submit_and_wait(&mut self, min_complete: u32) -> Result<(), linux_raw::Error> {
        let count = self.queue_length() as u32;
        if count == 0 {
            return Ok(());
        }

        (*self.submit_tail_pointer).store(self.submit_tail, Ordering::Release);
        (*self.completion_head_pointer).store(self.completion_head, Ordering::Release);
        let result = linux_raw::sys_io_uring_enter(
            self.fd.borrow(),
            count,
            min_complete,
            linux_raw::IORING_ENTER_GETEVENTS,
            core::ptr::null_mut(),
            0,
        );
        self.submit_head = (*self.submit_head_pointer).load(Ordering::Acquire);
        self.completion_tail = (*self.completion_tail_pointer).load(Ordering::Acquire);

        result?;
        Ok(())
    }

    pub fn finished_count(&self) -> usize {
        self.completion_tail.wrapping_sub(self.completion_head) as usize
    }

    pub fn pop_finished(&mut self) -> Option<linux_raw::io_uring_cqe> {
        if self.finished_count() == 0 {
            return None;
        }

        let index = self.completion_head & self.completion_ring_mask;
        let event = unsafe { self.cqes.add(index as usize).read() };
        self.completion_head = self.completion_head.wrapping_add(1);
        Some(event)
    }
}

impl linux_raw::io_uring_cqe {
    pub fn to_result(&self) -> Result<i32, linux_raw::Error> {
        linux_raw::Error::from_syscall("io_uring", i64::from(self.res))?;
        Ok(self.res)
    }
}

#[allow(clippy::unwrap_used)]
#[test]
fn test_io_uring_read() {
    let mut io_uring = IoUring::new(2).unwrap();
    let fd = crate::sys_open(crate::cstr!("/dev/zero"), crate::O_CLOEXEC).unwrap();

    let mut buffer = [0xff; 5];
    assert_eq!(io_uring.queue_length(), 0);
    io_uring.queue_read(0x1234, fd.borrow(), buffer.as_mut_ptr(), 1).unwrap();
    assert_eq!(io_uring.queue_length(), 1);
    io_uring.queue_read(0x1235, fd.borrow(), buffer[2..].as_mut_ptr(), 2).unwrap();
    assert_eq!(io_uring.queue_length(), 2);
    assert_eq!(io_uring.finished_count(), 0);
    unsafe {
        io_uring.submit_and_wait(2).unwrap();
    }
    assert_eq!(io_uring.queue_length(), 0);
    assert_eq!(io_uring.finished_count(), 2);
    assert_eq!(buffer, [0, 0xff, 0, 0, 0xff]);

    let mut completion_1 = io_uring.pop_finished().unwrap();
    let mut completion_2 = io_uring.pop_finished().unwrap();
    let completion_3 = io_uring.pop_finished();
    assert!(completion_3.is_none());

    if completion_1.user_data == 0x1235 {
        core::mem::swap(&mut completion_1, &mut completion_2);
    }

    assert_eq!(completion_1.user_data, 0x1234);
    assert_eq!(completion_1.res, 1);
    assert_eq!(completion_2.user_data, 0x1235);
    assert_eq!(completion_2.res, 2);
}

#[cfg(test)]
fn get_kernel_version() -> Result<(u32, u32), linux_raw::Error> {
    let uname = crate::sys_uname()?;
    let Ok(release) = unsafe { core::ffi::CStr::from_ptr(uname.release.as_ptr().cast()) }.to_str() else {
        return Err(linux_raw::Error::from_str(
            "failed to parse the kernel's release string: not valid UTF-8",
        ));
    };

    let mut iter = release.split('.');
    let Some(major) = iter.next().and_then(|major| major.parse::<u32>().ok()) else {
        return Err(linux_raw::Error::from_str("failed to extract the kernel's major version"));
    };

    let Some(minor) = iter.next().and_then(|minor| minor.parse::<u32>().ok()) else {
        return Err(linux_raw::Error::from_str("failed to extract the kernel's minor version"));
    };

    Ok((major, minor))
}

#[allow(clippy::unwrap_used)]
#[test]
fn test_io_uring_futex_wait() {
    extern crate std;
    use std::sync::Arc;

    // TODO: Check for the feature like liburing does ('io_uring_opcode_supported(ring->probe, IORING_OP_FUTEX_WAIT)')
    let (major, minor) = get_kernel_version().unwrap();
    if !(major > 6 || (major == 6 && minor > 7)) {
        return;
    }

    let futex = Arc::new(AtomicU32::new(0));
    let mut io_uring = IoUring::new(2).unwrap();
    io_uring.queue_futex_wait(0x1234, &*futex, 0).unwrap();

    let futex_clone = Arc::clone(&futex);
    std::thread::spawn(move || {
        std::thread::sleep(core::time::Duration::from_millis(25));
        futex_clone.store(1, Ordering::Relaxed);
        crate::sys_futex_wake_one(&futex_clone).unwrap();
    });

    unsafe {
        io_uring.submit_and_wait(1).unwrap();
    }
    let completion = io_uring.pop_finished().unwrap();
    completion.to_result().unwrap();
    assert_eq!(futex.load(Ordering::Relaxed), 1);
}

#[allow(clippy::unwrap_used)]
#[test]
fn test_io_uring_futex_wake() {
    extern crate std;
    use std::sync::Arc;

    // TODO: Check for the feature like liburing does ('io_uring_opcode_supported(ring->probe, IORING_OP_FUTEX_WAIT)')
    let (major, minor) = get_kernel_version().unwrap();
    if !(major > 6 || (major == 6 && minor > 7)) {
        return;
    }

    let futex = Arc::new(AtomicU32::new(0));
    let futex_clone = Arc::clone(&futex);
    std::thread::spawn(move || {
        std::thread::sleep(core::time::Duration::from_millis(25));
        futex_clone.store(1, Ordering::Relaxed);
        let mut io_uring = IoUring::new(2).unwrap();
        io_uring.queue_futex_wake_one(0x1234, &*futex_clone).unwrap();
        unsafe {
            io_uring.submit_and_wait(1).unwrap();
        }
        let completion = io_uring.pop_finished().unwrap();
        completion.to_result().unwrap();
    });

    linux_raw::sys_futex_wait(&futex, 0, Some(core::time::Duration::from_secs(1))).unwrap();
    assert_eq!(futex.load(Ordering::Relaxed), 1);
}
