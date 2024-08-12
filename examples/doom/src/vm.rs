use core::mem::MaybeUninit;
use polkavm::{CallError, Caller, Config, Engine, Instance, Linker, Module, ModuleConfig, ProgramBlob};

struct State {
    rom: Vec<u8>,
    frame: Vec<u8>,
    frame_width: u32,
    frame_height: u32,
    audio_buffer: Vec<i16>,
    #[allow(clippy::type_complexity)]
    on_audio_frame: Option<Box<dyn FnMut(&[i16])>>,
}

pub type Error = Box<dyn std::error::Error>;

pub struct Vm {
    state: State,
    instance: Instance<State, Error>,
}

impl Vm {
    pub fn from_blob(blob: ProgramBlob) -> Result<Self, polkavm::Error> {
        let config = Config::from_env()?;
        let engine = Engine::new(&config)?;
        let mut module_config = ModuleConfig::new();
        module_config.set_page_size(0x4000);
        let module = Module::from_blob(&engine, &module_config, blob)?;
        let mut linker = Linker::new();

        linker.define_typed(
            "ext_output_video",
            |caller: Caller<State>, address: u32, width: u32, height: u32| -> Result<(), Error> {
                let length = width * height * 4;
                caller.user_data.frame.clear();
                caller.user_data.frame.reserve(length as usize);
                caller
                    .instance
                    .read_memory_into(address, &mut caller.user_data.frame.spare_capacity_mut()[..length as usize])?;
                unsafe {
                    caller.user_data.frame.set_len(length as usize);
                }
                caller.user_data.frame_width = width;
                caller.user_data.frame_height = height;

                Ok(())
            },
        )?;

        linker.define_typed(
            "ext_output_audio",
            |caller: Caller<State>, address: u32, samples: u32| -> Result<(), Error> {
                let Some(on_audio_frame) = caller.user_data.on_audio_frame.as_mut() else {
                    return Ok(());
                };

                caller.user_data.audio_buffer.reserve(samples as usize * 2);

                {
                    let audio_buffer: &mut [MaybeUninit<i16>] =
                        &mut caller.user_data.audio_buffer.spare_capacity_mut()[..samples as usize * 2];
                    let audio_buffer: &mut [MaybeUninit<u8>] = unsafe {
                        core::slice::from_raw_parts_mut(audio_buffer.as_mut_ptr().cast(), audio_buffer.len() * core::mem::size_of::<i16>())
                    };
                    caller.instance.read_memory_into(address, audio_buffer)?;
                }

                unsafe {
                    let new_length = caller.user_data.audio_buffer.len() + samples as usize * 2;
                    caller.user_data.audio_buffer.set_len(new_length);
                }

                on_audio_frame(&caller.user_data.audio_buffer);
                caller.user_data.audio_buffer.clear();
                Ok(())
            },
        )?;

        linker.define_typed("ext_rom_size", |caller: Caller<State>| -> u32 { caller.user_data.rom.len() as u32 })?;

        linker.define_typed(
            "ext_rom_read",
            |caller: Caller<State>, pointer: u32, offset: u32, length: u32| -> Result<(), Error> {
                let chunk = caller
                    .user_data
                    .rom
                    .get(offset as usize..offset as usize + length as usize)
                    .ok_or_else(|| format!("invalid ROM read: offset = 0x{offset:x}, length = {length}"))?;

                Ok(caller.instance.write_memory(pointer, chunk)?)
            },
        )?;

        linker.define_typed(
            "ext_stdout",
            |caller: Caller<State>, buffer: u32, length: u32| -> Result<i32, Error> {
                if length == 0 {
                    return Ok(0);
                }

                use std::io::Write;
                let buffer = caller.instance.read_memory(buffer, length)?;
                let stdout = std::io::stdout();
                let mut stdout = stdout.lock();
                if stdout.write_all(&buffer).is_ok() {
                    Ok(buffer.len() as i32)
                } else {
                    Ok(-32) // EPIPE
                }
            },
        )?;

        let instance_pre = linker.instantiate_pre(&module)?;
        let instance = instance_pre.instantiate()?;

        Ok(Self {
            state: State {
                rom: Default::default(),
                frame: Default::default(),
                frame_width: 0,
                frame_height: 0,
                audio_buffer: Default::default(),
                on_audio_frame: None,
            },
            instance,
        })
    }

    pub fn set_on_audio_frame(&mut self, callback: impl FnMut(&[i16]) + 'static) {
        self.state.on_audio_frame = Some(Box::new(callback));
    }

    pub fn initialize(&mut self, rom: impl Into<Vec<u8>>) -> Result<(), CallError<Error>> {
        self.state.rom = rom.into();
        self.instance.call_typed(&mut self.state, "ext_initialize", ())
    }

    pub fn run_for_a_frame(&mut self) -> Result<(u32, u32, &[u8]), CallError<Error>> {
        self.instance.call_typed(&mut self.state, "ext_tick", ())?;
        Ok((self.state.frame_width, self.state.frame_height, &self.state.frame))
    }

    pub fn on_keychange(&mut self, key: u8, is_pressed: bool) -> Result<(), CallError<Error>> {
        self.instance
            .call_typed(&mut self.state, "ext_on_keychange", (key as u32, is_pressed as u32))
    }
}
