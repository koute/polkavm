pub struct Reader<'a> {
    pub buffer: &'a [u8],
    pub bytes_consumed: usize,
}

impl<'a> Reader<'a> {
    pub fn read(&mut self, length: usize) -> Result<&'a [u8], &'static str> {
        let subslice = self.buffer.get(..length).ok_or("unexpected end of section")?;
        self.buffer = &self.buffer[length..];
        self.bytes_consumed += length;
        Ok(subslice)
    }

    pub fn read_byte(&mut self) -> Result<u8, &'static str> {
        Ok(self.read(1)?[0])
    }

    pub fn read_u32(&mut self) -> Result<u32, &'static str> {
        let v = self.read(4)?;
        Ok(u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
    }

    pub fn read_u64(&mut self) -> Result<u64, &'static str> {
        let v = self.read(8)?;
        Ok(u64::from_le_bytes([v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]]))
    }

    pub fn offset(&self) -> usize {
        self.bytes_consumed
    }

    pub fn is_empty(&self) -> bool {
        self.bytes_consumed >= self.buffer.len()
    }
}

impl<'a> From<&'a [u8]> for Reader<'a> {
    fn from(buffer: &'a [u8]) -> Self {
        Reader { buffer, bytes_consumed: 0 }
    }
}
