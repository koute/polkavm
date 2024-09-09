#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash(pub [u8; 32]);

impl From<[u8; 32]> for Hash {
    fn from(hash: [u8; 32]) -> Self {
        Self(hash)
    }
}

impl core::fmt::Display for Hash {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        for &byte in &self.0 {
            write!(fmt, "{:02x}", byte)?;
        }

        Ok(())
    }
}

impl core::fmt::Debug for Hash {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        for &byte in &self.0 {
            write!(fmt, "Hash({:02x})", byte)?;
        }

        Ok(())
    }
}

pub struct Hasher {
    #[cfg(not(feature = "blake3"))]
    inner: crate::blake3::Hasher,
    #[cfg(feature = "blake3")]
    inner: blake3::Hasher,
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    pub fn new() -> Self {
        Self {
            #[cfg(not(feature = "blake3"))]
            inner: crate::blake3::Hasher::new(),
            #[cfg(feature = "blake3")]
            inner: blake3::Hasher::new(),
        }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
    }

    pub fn update_u32_array<const N: usize>(&mut self, values: [u32; N]) {
        if cfg!(target_endian = "little") {
            let new_length = values.len().checked_mul(4).expect("overflow");

            // SAFETY: An u32 slice can always be safely reinterpreted as an u8 slice.
            #[allow(unsafe_code)]
            let bytes: &[u8] = unsafe { core::slice::from_raw_parts(values.as_ptr().cast::<u8>(), new_length) };

            self.update(bytes)
        } else {
            for value in values {
                self.update(&value.to_le_bytes());
            }
        }
    }

    pub fn finalize(&self) -> Hash {
        #[cfg(not(feature = "blake3"))]
        {
            let mut hash = [0; 32];
            self.inner.finalize(&mut hash);
            Hash(hash)
        }
        #[cfg(feature = "blake3")]
        {
            let h = self.inner.finalize();
            Hash(*h.as_bytes())
        }
    }
}
