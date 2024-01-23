use core::cell::RefCell;
use gimli::Format;
use gimli::ReaderOffset;
use gimli::ReaderOffsetId;
use gimli::Result;
use std::borrow::Cow;
use std::rc::Rc;

#[derive(Debug)]
struct TrackerImpl<R>
where
    R: gimli::Reader,
{
    start: R,
    is_enabled: bool,
    list: Vec<u64>,
}

pub struct ReaderTracker<R>
where
    R: gimli::Reader,
{
    tracker: Rc<RefCell<TrackerImpl<R>>>,
}

impl<R> ReaderTracker<R>
where
    R: gimli::Reader,
{
    pub fn list(&self) -> core::cell::Ref<[u64]> {
        core::cell::Ref::map(self.tracker.borrow(), |tracker| tracker.list.as_slice())
    }
}

impl<R> Drop for ReaderTracker<R>
where
    R: gimli::Reader,
{
    fn drop(&mut self) {
        self.tracker.borrow_mut().is_enabled = false;
    }
}

/// A wrapper over a `gimli::Reader` which allows us to track the offsets from which we're reading.
#[derive(Clone, Debug)]
pub struct ReaderWrapper<R>
where
    R: gimli::Reader,
{
    inner: R,
    tracker: Rc<RefCell<TrackerImpl<R>>>,
}

impl<R> ReaderWrapper<R>
where
    R: gimli::Reader,
{
    pub fn wrap(reader: R) -> Self {
        let tracker = Rc::new(RefCell::new(TrackerImpl {
            start: reader.clone(),
            is_enabled: false,
            list: Vec::new(),
        }));
        ReaderWrapper { inner: reader, tracker }
    }

    pub fn start_tracking(&self) -> ReaderTracker<R> {
        {
            assert!(!self.tracker.borrow().is_enabled);
            let mut tracker = self.tracker.borrow_mut();
            tracker.is_enabled = true;
            tracker.list.clear();
        }
        ReaderTracker {
            tracker: Rc::clone(&self.tracker),
        }
    }

    fn track(&self) {
        let mut tracker = self.tracker.borrow_mut();
        if !tracker.is_enabled {
            return;
        }

        let offset = self.inner.offset_from(&tracker.start);
        tracker.list.push(offset.into_u64());
    }
}

impl<R> gimli::Reader for ReaderWrapper<R>
where
    R: gimli::Reader,
{
    type Endian = <R as gimli::Reader>::Endian;
    type Offset = <R as gimli::Reader>::Offset;

    fn endian(&self) -> Self::Endian {
        self.inner.endian()
    }

    fn len(&self) -> Self::Offset {
        self.inner.len()
    }

    fn empty(&mut self) {
        self.inner.empty()
    }

    fn truncate(&mut self, len: Self::Offset) -> Result<()> {
        self.inner.truncate(len)
    }

    fn offset_from(&self, base: &Self) -> Self::Offset {
        self.inner.offset_from(&base.inner)
    }

    fn offset_id(&self) -> ReaderOffsetId {
        self.inner.offset_id()
    }

    fn lookup_offset_id(&self, id: ReaderOffsetId) -> Option<Self::Offset> {
        self.inner.lookup_offset_id(id)
    }

    fn find(&self, byte: u8) -> Result<Self::Offset> {
        self.inner.find(byte)
    }

    fn skip(&mut self, len: Self::Offset) -> Result<()> {
        self.inner.skip(len)
    }

    fn split(&mut self, len: Self::Offset) -> Result<Self> {
        Ok(Self {
            inner: self.inner.split(len)?,
            tracker: Rc::clone(&self.tracker),
        })
    }

    fn to_slice(&self) -> Result<Cow<'_, [u8]>> {
        self.inner.to_slice()
    }

    fn to_string(&self) -> Result<Cow<'_, str>> {
        self.inner.to_string()
    }

    fn to_string_lossy(&self) -> Result<Cow<'_, str>> {
        self.inner.to_string_lossy()
    }

    fn read_slice(&mut self, buf: &mut [u8]) -> Result<()> {
        self.track();
        self.inner.read_slice(buf)
    }

    fn read_u8_array<A>(&mut self) -> Result<A>
    where
        A: Sized + Default + AsMut<[u8]>,
    {
        self.track();
        self.inner.read_u8_array::<A>()
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn read_u8(&mut self) -> Result<u8> {
        self.track();
        self.inner.read_u8()
    }

    fn read_i8(&mut self) -> Result<i8> {
        self.track();
        self.inner.read_i8()
    }

    fn read_u16(&mut self) -> Result<u16> {
        self.track();
        self.inner.read_u16()
    }

    fn read_i16(&mut self) -> Result<i16> {
        self.track();
        self.inner.read_i16()
    }

    fn read_u32(&mut self) -> Result<u32> {
        self.track();
        self.inner.read_u32()
    }

    fn read_i32(&mut self) -> Result<i32> {
        self.track();
        self.inner.read_i32()
    }

    fn read_u64(&mut self) -> Result<u64> {
        self.track();
        self.inner.read_u64()
    }

    fn read_i64(&mut self) -> Result<i64> {
        self.track();
        self.inner.read_i64()
    }

    fn read_f32(&mut self) -> Result<f32> {
        self.track();
        self.inner.read_f32()
    }

    fn read_f64(&mut self) -> Result<f64> {
        self.track();
        self.inner.read_f64()
    }

    fn read_uint(&mut self, n: usize) -> Result<u64> {
        self.track();
        self.inner.read_uint(n)
    }

    fn read_null_terminated_slice(&mut self) -> Result<Self> {
        self.track();
        Ok(Self {
            inner: self.inner.read_null_terminated_slice()?,
            tracker: Rc::clone(&self.tracker),
        })
    }

    fn skip_leb128(&mut self) -> Result<()> {
        self.track();
        self.inner.skip_leb128()
    }

    fn read_uleb128(&mut self) -> Result<u64> {
        self.track();
        self.inner.read_uleb128()
    }

    fn read_uleb128_u32(&mut self) -> Result<u32> {
        self.track();
        self.inner.read_uleb128_u32()
    }

    fn read_uleb128_u16(&mut self) -> Result<u16> {
        self.track();
        self.inner.read_uleb128_u16()
    }

    fn read_sleb128(&mut self) -> Result<i64> {
        self.track();
        self.inner.read_sleb128()
    }

    fn read_initial_length(&mut self) -> Result<(Self::Offset, Format)> {
        self.track();
        self.inner.read_initial_length()
    }

    fn read_address(&mut self, address_size: u8) -> Result<u64> {
        self.track();
        self.inner.read_address(address_size)
    }

    fn read_word(&mut self, format: Format) -> Result<Self::Offset> {
        self.track();
        self.inner.read_word(format)
    }

    fn read_length(&mut self, format: Format) -> Result<Self::Offset> {
        self.track();
        self.inner.read_length(format)
    }

    fn read_offset(&mut self, format: Format) -> Result<Self::Offset> {
        self.track();
        self.inner.read_offset(format)
    }

    fn read_sized_offset(&mut self, size: u8) -> Result<Self::Offset> {
        self.track();
        self.inner.read_sized_offset(size)
    }
}
