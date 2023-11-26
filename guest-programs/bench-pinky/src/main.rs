#![no_std]
#![no_main]

include!("../../bench-common.rs");

use nes::Interface;

struct Emulator {
    state: nes::State,
}

impl nes::Context for Emulator {
    fn state(&self) -> &nes::State {
        &self.state
    }

    fn state_mut(&mut self) -> &mut nes::State {
        &mut self.state
    }
}

// Source of the ROM: https://github.com/christopherpow/nes-test-roms/tree/97720008e51db15dd281a2a1e64d4c65cf1bca4c/nes15-1.0.0
// Licensed under a BSD-style license.
const ROM: &[u8] = core::include_bytes!("nes15-NTSC.nes");

struct State {
    nes: Emulator,
    framebuffer: Option<Box<[u32; 256 * 240]>>,
}

define_benchmark! {
    heap_size = 512 * 1024,
    state = State {
        nes: Emulator { state: nes::State::new() },
        framebuffer: None,
    },
}

#[inline]
unsafe fn alloc_zeroed_box<T>() -> Box<T> {
    Box::from_raw(alloc::alloc::alloc_zeroed(alloc::alloc::Layout::new::<T>()) as *mut T)
}

fn benchmark_initialize(state: &mut State) {
    state.framebuffer = Some(unsafe { alloc_zeroed_box() });
    state.nes.load_rom(ROM).unwrap();

    // By default the game which we're emulating stays on the main menu
    // screen without anything happening on screen; it doesn't even try
    // to play any music.
    //
    // Pressing any button on the gamepad actually starts the game, and
    // once the game is started pressing the select button triggers
    // an autosolve mechanism which makes the game automatically play itself.
    //
    // So let's trigger this here.

    // We need to wait for four frames until the game accepts any input.
    //
    // I don't know why; I just started to empirically increase the number
    // of frames until it worked.
    for _ in 0..4 {
        state.nes.execute_until_vblank().unwrap();
    }

    // Now we can press a button to start the game.
    state.nes.press(nes::ControllerPort::First, nes::Button::Select);
    state.nes.execute_until_vblank().unwrap();
    state.nes.release(nes::ControllerPort::First, nes::Button::Select);

    // We need to wait for at least three frames until we can trigger
    // the autosolve mechanism.
    for _ in 0..3 {
        state.nes.execute_until_vblank().unwrap();
    }

    // Now we can press select to make the game start playing itself.
    state.nes.press(nes::ControllerPort::First, nes::Button::Select);
    state.nes.execute_until_vblank().unwrap();
    state.nes.release(nes::ControllerPort::First, nes::Button::Select);
}

fn benchmark_run(state: &mut State) {
    state.nes.execute_until_vblank().unwrap();
    state
        .nes
        .framebuffer()
        .convert_to_abgr(&nes::Palette::default(), &mut state.framebuffer.as_mut().unwrap()[..]);
}

// Used by unit tests.
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
#[polkavm_derive::polkavm_export]
#[no_mangle]
extern "C" fn get_framebuffer() -> usize {
    unsafe { STATE.framebuffer.as_mut().unwrap().as_mut_ptr() as usize }
}
