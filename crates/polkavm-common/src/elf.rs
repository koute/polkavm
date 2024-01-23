use crate::program::ExternTy;

/// Custom instruction used to make an external function call.
///
/// These are processed when relinking the ELf file and will *not* end up in the final payload.
pub const INSTRUCTION_ECALLI: u32 = 0x0000000b;

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

/// Function prototype metadata. Serialized by the derive macro and deserialized when relinking the ELF file.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FnMetadata {
    pub name: alloc::string::String,
    pub return_ty: Option<ExternTy>,
    pub args: [Option<ExternTy>; crate::abi::VM_MAXIMUM_EXTERN_ARG_COUNT],
}

impl FnMetadata {
    pub fn new(name: impl Into<alloc::string::String>, args: &[ExternTy], return_ty: Option<ExternTy>) -> Self {
        assert!(args.len() <= crate::abi::VM_MAXIMUM_EXTERN_ARG_COUNT);

        let mut args_array = [None; crate::abi::VM_MAXIMUM_EXTERN_ARG_COUNT];
        for (slot, arg) in args_array.iter_mut().zip(args.iter()) {
            *slot = Some(*arg);
        }

        FnMetadata {
            name: name.into(),
            return_ty,
            args: args_array,
        }
    }

    pub fn args(&self) -> impl Iterator<Item = ExternTy> + '_ {
        self.args.iter().take_while(|arg| arg.is_some()).flatten().copied()
    }

    pub fn return_ty(&self) -> Option<ExternTy> {
        self.return_ty
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn serialize(&self, mut cb: impl FnMut(&[u8])) {
        cb(&(self.name.len() as u32).to_le_bytes());
        cb(self.name.as_bytes());
        cb(&[self.return_ty.map_or(0, |ty| ty as u8)]);
        cb(&[self.args().count() as u8]);
        for arg in self.args() {
            cb(&[arg as u8]);
        }
    }

    pub fn try_deserialize(b: &mut Reader) -> Result<Self, &'static str> {
        let name_length = b.read_u32()? as usize;
        let name = core::str::from_utf8(b.read(name_length)?).map_err(|_| "name of the import is not valid UTF-8")?;
        let return_ty = b.read_byte()?;
        let return_ty = if return_ty == 0 {
            None
        } else {
            Some(ExternTy::try_deserialize(return_ty).ok_or("invalid return type")?)
        };
        let arg_count = b.read_byte()? as usize;
        if arg_count > crate::abi::VM_MAXIMUM_EXTERN_ARG_COUNT {
            return Err("too many arguments");
        }

        let mut args = [None; crate::abi::VM_MAXIMUM_EXTERN_ARG_COUNT];

        #[allow(clippy::needless_range_loop)]
        for n in 0..arg_count {
            args[n] = Some(ExternTy::try_deserialize(b.read_byte()?).ok_or("invalid argument type")?);
        }

        Ok(Self {
            name: name.into(),
            return_ty,
            args,
        })
    }
}

/// Import metadata. Serialized by the derive macro and deserialized when relinking the ELF file.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ImportMetadata {
    pub index: Option<u32>,
    pub prototype: FnMetadata,
}

impl ImportMetadata {
    pub fn prototype(&self) -> &FnMetadata {
        &self.prototype
    }

    pub fn args(&self) -> impl Iterator<Item = ExternTy> + '_ {
        self.prototype.args()
    }

    pub fn return_ty(&self) -> Option<ExternTy> {
        self.prototype.return_ty()
    }

    pub fn name(&self) -> &str {
        self.prototype.name()
    }

    pub fn try_deserialize(b: &[u8]) -> Result<(usize, Self), &'static str> {
        let mut b: Reader = b.into();

        let version = b.read_byte()?;
        if version != 1 {
            return Err("unsupported version");
        }

        let index = match b.read_byte()? {
            0 => None,
            1 => Some(b.read_u32()?),
            _ => return Err("invalid index"),
        };

        let prototype = FnMetadata::try_deserialize(&mut b)?;
        Ok((b.bytes_consumed, Self { index, prototype }))
    }
}
