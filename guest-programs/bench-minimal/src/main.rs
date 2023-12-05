#![no_std]
#![no_main]

include!("../../bench-common.rs");

struct State {
    counter: u32,
    function: fn(&mut State),
}

define_benchmark! {
    heap_size = 0,
    state = State {
        counter: 0,
        function: dummy_even,
    },
}

static TABLE: [fn(&mut State); 2] = [dummy_even, dummy_odd];

fn dummy_odd(state: &mut State) {
    state.counter = state.counter.wrapping_add(1);
}

fn dummy_even(state: &mut State) {
    state.counter = state.counter.wrapping_add(3);
}

fn benchmark_initialize(_state: &mut State) {}
fn benchmark_run(state: &mut State) {
    (state.function)(state);
    state.function = TABLE[state.counter as usize % 2];
}
