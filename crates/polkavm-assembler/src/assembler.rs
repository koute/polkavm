#[derive(Copy, Clone)]
struct Fixup {
    target_label: Label,
    instruction_offset: usize,
    instruction_length: u8,
    fixup_offset: u8,
    fixup_length: u8,
}

pub struct Assembler {
    origin: u64,
    code: Vec<u8>,
    labels: Vec<usize>,
    fixups: Vec<Fixup>,
}

#[allow(clippy::derivable_impls)]
impl Default for Assembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Assembler {
    pub const fn new() -> Self {
        Assembler {
            origin: 0,
            code: Vec::new(),
            labels: Vec::new(),
            fixups: Vec::new(),
        }
    }

    pub fn set_origin(&mut self, origin: u64) {
        self.origin = origin;
    }

    pub fn current_address(&self) -> u64 {
        self.origin + self.code.len() as u64
    }

    pub fn forward_declare_label(&mut self) -> Label {
        let label = self.labels.len();
        self.labels.push(usize::MAX);
        Label(label)
    }

    pub fn create_label(&mut self) -> Label {
        let label = self.labels.len();
        self.labels.push(self.code.len());
        Label(label)
    }

    pub fn define_label(&mut self, label: Label) -> &mut Self {
        assert_eq!(self.labels[label.0], usize::MAX, "tried to redefine an already defined label");
        self.labels[label.0] = self.code.len();
        self
    }

    pub fn push_with_label(&mut self, label: Label, inst: impl Instruction) -> &mut Self {
        self.define_label(label);
        self.push(inst)
    }

    pub fn get_label_offset(&self, label: Label) -> usize {
        let offset = self.labels[label.0];
        assert_ne!(offset, usize::MAX, "tried to fetch a label offset for a label that was not defined");
        offset
    }

    fn add_fixup_if_necessary(&mut self, bytes: &[u8], inst: impl Instruction) {
        let (target_label, fixup_offset, fixup_length) = match inst.target_fixup() {
            Some(fixup) => fixup,
            None => return,
        };

        assert!(target_label.0 < self.labels.len());
        assert!(
            (fixup_offset as usize) < bytes.len(),
            "instruction is {} bytes long and yet its target fixup starts at {}",
            bytes.len(),
            fixup_offset
        );
        assert!((fixup_length as usize) < bytes.len());
        assert!((fixup_offset as usize + fixup_length as usize) <= bytes.len());
        self.fixups.push(Fixup {
            target_label,
            instruction_offset: self.code.len(),
            instruction_length: bytes.len() as u8,
            fixup_offset,
            fixup_length,
        });
    }

    pub fn push(&mut self, inst: impl Instruction) -> &mut Self {
        let enc = inst.encode();
        let bytes = enc.as_bytes();
        self.add_fixup_if_necessary(bytes, inst);
        log::trace!("{:08x}: {}", self.origin + self.code.len() as u64, inst);

        self.code.extend_from_slice(bytes);
        self
    }

    pub fn finalize(&mut self) -> &[u8] {
        for fixup in self.fixups.drain(..) {
            let origin = fixup.instruction_offset + fixup.instruction_length as usize;
            let target_absolute = self.labels[fixup.target_label.0];
            assert_ne!(target_absolute, usize::MAX);
            let offset = target_absolute as isize - origin as isize;
            let p = fixup.instruction_offset + fixup.fixup_offset as usize;
            if fixup.fixup_length == 1 {
                if offset > i8::MAX as isize || offset < i8::MIN as isize {
                    panic!("out of range jump");
                }
                self.code[p] = offset as i8 as u8;
            } else if fixup.fixup_length == 4 {
                if offset > i32::MAX as isize || offset < i32::MIN as isize {
                    panic!("out of range jump");
                }
                self.code[p..p + 4].copy_from_slice(&(offset as i32).to_le_bytes());
            } else {
                unreachable!()
            }
        }
        &self.code
    }

    pub fn is_empty(&self) -> bool {
        self.code.is_empty()
    }

    pub fn len(&self) -> usize {
        self.code.len()
    }

    pub fn clear(&mut self) {
        self.origin = 0;
        self.code.clear();
        self.labels.clear();
        self.fixups.clear();
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct Label(usize);

impl core::fmt::Display for Label {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.write_fmt(core::format_args!("<{}>", self.0))
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(align(8))]
pub struct EncInst {
    bytes: [u8; 15],
    length: u8,
}

impl EncInst {
    pub const fn new() -> Self {
        Self::from_array([])
    }

    pub const fn from_array<const N: usize>(array: [u8; N]) -> Self {
        let mut out = EncInst { bytes: [0; 15], length: 0 };

        let mut n = 0;
        while n < N {
            out.bytes[n] = array[n];
            n += 1;
        }
        out.length = N as u8;
        out
    }

    pub const fn len(self) -> usize {
        self.length as usize
    }

    pub const fn is_empty(self) -> bool {
        self.len() == 0
    }

    pub const fn append(self, byte: u8) -> Self {
        self.append_array([byte])
    }

    pub const fn append_array_if<const N: usize>(self, condition: bool, array: [u8; N]) -> Self {
        if condition {
            self.append_array::<N>(array)
        } else {
            self
        }
    }

    pub const fn append_array<const N: usize>(mut self, array: [u8; N]) -> Self {
        let mut p = self.length as usize;
        assert!(p + N < 16);

        let mut n = 0;
        while n < N {
            self.bytes[p] = array[n];
            p += 1;
            n += 1;
        }

        self.length += N as u8;
        self
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length as usize]
    }
}

impl AsRef<[u8]> for EncInst {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

pub trait Instruction: Copy + core::fmt::Display {
    fn encode(self) -> EncInst;
    fn target_fixup(self) -> Option<(Label, u8, u8)>;
}
