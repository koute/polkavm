use core::mem::MaybeUninit;
use polkavm::{Caller, Config, Engine, ExecutionError, Linker, Module, ProgramBlob, Trap, TypedFunc};

struct State {
    rom: Vec<u8>,
    frame: Vec<u8>,
    frame_width: u32,
    frame_height: u32,
    audio_buffer: Vec<i16>,
    #[allow(clippy::type_complexity)]
    on_audio_frame: Option<Box<dyn FnMut(&[i16])>>,
}

pub struct Vm {
    state: State,
    ext_initialize: TypedFunc<State, (), ()>,
    ext_tick: TypedFunc<State, (), ()>,
    ext_on_keychange: TypedFunc<State, (u32, u32), ()>,
}

impl Vm {
    pub fn from_blob(blob: ProgramBlob) -> Result<Self, polkavm::Error> {
        let config = Config::from_env()?;
        let engine = Engine::new(&config)?;
        let module = Module::from_blob(&engine, &blob)?;
        let mut linker = Linker::new(&engine);

        linker.func_wrap(
            "ext_output_video",
            |caller: Caller<State>, address: u32, width: u32, height: u32| -> Result<(), Trap> {
                let (caller, state) = caller.split();
                let length = width * height * 4;
                state.frame.clear();
                state.frame.reserve(length as usize);
                caller.read_memory_into_slice(address, &mut state.frame.spare_capacity_mut()[..length as usize])?;
                unsafe {
                    state.frame.set_len(length as usize);
                }
                state.frame_width = width;
                state.frame_height = height;

                Ok(())
            },
        )?;

        linker.func_wrap(
            "ext_output_audio",
            |caller: Caller<State>, address: u32, samples: u32| -> Result<(), Trap> {
                let (caller, state) = caller.split();
                let Some(on_audio_frame) = state.on_audio_frame.as_mut() else {
                    return Ok(());
                };

                state.audio_buffer.reserve(samples as usize * 2);

                {
                    let audio_buffer: &mut [MaybeUninit<i16>] = &mut state.audio_buffer.spare_capacity_mut()[..samples as usize * 2];
                    let audio_buffer: &mut [MaybeUninit<u8>] = unsafe {
                        core::slice::from_raw_parts_mut(audio_buffer.as_mut_ptr().cast(), audio_buffer.len() * core::mem::size_of::<i16>())
                    };
                    caller.read_memory_into_slice(address, audio_buffer)?;
                }

                unsafe {
                    let new_length = state.audio_buffer.len() + samples as usize * 2;
                    state.audio_buffer.set_len(new_length);
                }

                on_audio_frame(&state.audio_buffer);
                state.audio_buffer.clear();
                Ok(())
            },
        )?;

        linker.func_wrap("ext_rom_size", |caller: Caller<State>| -> u32 { caller.data().rom.len() as u32 })?;

        linker.func_wrap(
            "ext_rom_read",
            |caller: Caller<State>, pointer: u32, offset: u32, length: u32| -> Result<(), Trap> {
                let (mut caller, state) = caller.split();
                let chunk = state
                    .rom
                    .get(offset as usize..offset as usize + length as usize)
                    .ok_or_else(Trap::default)?;

                caller.write_memory(pointer, chunk)
            },
        )?;

        linker.func_wrap(
            "ext_stdout",
            |caller: Caller<State>, buffer: u32, length: u32| -> Result<i32, Trap> {
                if length == 0 {
                    return Ok(0);
                }

                use std::io::Write;
                let buffer = caller.read_memory_into_new_vec(buffer, length)?;
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
        let ext_initialize = instance.get_typed_func::<(), ()>("ext_initialize")?;
        let ext_tick = instance.get_typed_func::<(), ()>("ext_tick")?;
        let ext_on_keychange = instance.get_typed_func::<(u32, u32), ()>("ext_on_keychange")?;

        Ok(Self {
            state: State {
                rom: Default::default(),
                frame: Default::default(),
                frame_width: 0,
                frame_height: 0,
                audio_buffer: Default::default(),
                on_audio_frame: None,
            },
            ext_initialize,
            ext_tick,
            ext_on_keychange,
        })
    }

    pub fn set_on_audio_frame(&mut self, callback: impl FnMut(&[i16]) + 'static) {
        self.state.on_audio_frame = Some(Box::new(callback));
    }

    pub fn initialize(&mut self, rom: impl Into<Vec<u8>>) -> Result<(), ExecutionError<polkavm::Error>> {
        self.state.rom = rom.into();
        self.ext_initialize.call(&mut self.state, ())
    }

    pub fn run_for_a_frame(&mut self) -> Result<(u32, u32, &[u8]), ExecutionError<polkavm::Error>> {
        self.ext_tick.call(&mut self.state, ())?;
        Ok((self.state.frame_width, self.state.frame_height, &self.state.frame))
    }

    pub fn on_keychange(&mut self, key: u8, is_pressed: bool) -> Result<(), ExecutionError<polkavm::Error>> {
        self.ext_on_keychange.call(&mut self.state, (key as u32, is_pressed as u32))
    }
}
