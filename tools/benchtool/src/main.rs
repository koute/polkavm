use clap::Parser;
#[cfg(feature = "criterion")]
use criterion::*;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use {
    crate::backend::BackendKind,
    std::{
        ffi::OsString,
        process::Command,
        sync::atomic::{AtomicBool, Ordering},
        sync::{Arc, Barrier, Mutex},
    },
};

mod backend;
mod utils;

use crate::backend::Backend;

const FAST_INNER_COUNT: u32 = 32;
const SLOW_INNER_COUNT: u32 = 1;

fn benchmark_execution<T: Backend>(outer_count: u64, inner_count: u32, backend: T, path: &Path) -> core::time::Duration {
    let mut total_elapsed = core::time::Duration::new(0, 0);
    let mut engine = backend.create();
    let blob = backend.load(path);
    let module = backend.compile(&mut engine, &blob);
    for _ in 0..outer_count {
        let mut instance = backend.spawn(&mut engine, &module);
        backend.initialize(&mut instance);
        let start = std::time::Instant::now();
        for _ in 0..inner_count {
            backend.run(&mut instance);
        }
        total_elapsed += start.elapsed();
    }

    total_elapsed / inner_count
}

fn benchmark_compilation<T: Backend>(count: u64, backend: T, path: &Path) -> core::time::Duration {
    let mut engine = backend.create();
    let blob = backend.load(path);
    let start = std::time::Instant::now();
    for _ in 0..count {
        backend.compile(&mut engine, &blob);
    }
    start.elapsed()
}

#[cfg(feature = "criterion")]
fn criterion_main(c: &mut Criterion, benches: &[Benchmark]) {
    let mut by_name = std::collections::BTreeMap::new();
    for bench in benches {
        by_name.entry(bench.name.clone()).or_insert_with(Vec::new).push(bench);
    }

    for (name, variants) in &by_name {
        let mut group = c.benchmark_group(format!("runtime/{}", name));
        for bench in variants {
            for backend in bench.kind.matching_backends() {
                if backend.is_slow() {
                    // These are too slow for criterion; skip them.
                    continue;
                }

                group.bench_function(backend.name(), |b| {
                    b.iter_custom(|count| benchmark_execution(count, FAST_INNER_COUNT, backend, &bench.path));
                });
            }
        }
        group.finish();
    }

    for (name, variants) in &by_name {
        let mut group = c.benchmark_group(format!("compilation/{}", name));
        for bench in variants {
            for backend in bench.kind.matching_backends() {
                if !backend.is_compiled() {
                    continue;
                }

                group.bench_function(backend.name(), |b| {
                    b.iter_custom(|count| benchmark_compilation(count, backend, &bench.path));
                });
            }
        }
        group.finish();
    }
}

macro_rules! error {
    ($($args:tt)*) => {
        std::io::Error::new(std::io::ErrorKind::Other, format!($($args)*))
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Benchmark {
    pub name: String,
    pub kind: BenchmarkKind,
    pub path: PathBuf,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum BenchmarkKind {
    PolkaVM,
    WebAssembly,
    Ckbvm,
    Solana,
    Native,
}

fn find_benchmarks_in(root_path: &Path) -> Result<Vec<Benchmark>, std::io::Error> {
    let mut output = Vec::new();
    let entries = std::fs::read_dir(root_path).map_err(|error| error!("failed to read {root_path:?}: {error}"))?;
    for entry in entries {
        let entry = entry.map_err(|error| error!("failed to read file entry in {root_path:?}: {error}"))?;
        let path = entry.path();
        let Some(stem) = path.file_stem().and_then(OsStr::to_str) else {
            continue;
        };

        let Some(name) = stem
            .strip_prefix("bench-")
            .or_else(|| stem.strip_prefix("libbench_"))
            .or_else(|| stem.strip_prefix("bench_"))
        else {
            continue;
        };

        let target = path.parent().and_then(|path| path.parent()).and_then(|path| path.file_name());

        let kind = if let Some(extension) = path.extension() {
            if extension == "wasm" {
                BenchmarkKind::WebAssembly
            } else if extension == "polkavm" {
                BenchmarkKind::PolkaVM
            } else if extension == "so" {
                if target.as_ref().map(|target| *target == "sbf-solana-solana").unwrap_or(false) {
                    BenchmarkKind::Solana
                } else {
                    BenchmarkKind::Native
                }
            } else {
                continue;
            }
        } else {
            let Some(target) = target else { continue };
            if target == "riscv64imac-unknown-none-elf" {
                BenchmarkKind::Ckbvm
            } else {
                continue;
            }
        };

        output.push(Benchmark {
            name: name.replace('_', "-"),
            kind,
            path,
        });
    }

    Ok(output)
}

fn find_benchmarks() -> Result<Vec<Benchmark>, std::io::Error> {
    let mut output = Vec::new();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../guest-programs");
    let paths = [
        root.join("target/riscv32em-unknown-none-elf/release"),
        root.join("target/riscv64imac-unknown-none-elf/release"),
        root.join("target/wasm32-unknown-unknown/release"),
        root.join("target/sbf-solana-solana/release"),
        #[cfg(target_arch = "x86_64")]
        root.join("target/x86_64-unknown-linux-gnu/release"),
        #[cfg(target_arch = "x86")]
        root.join("target/i686-unknown-linux-gnu/release"),
        PathBuf::from("."),
    ];

    for path in paths {
        if !path.exists() {
            continue;
        }

        output.extend(find_benchmarks_in(&path)?);
    }

    output.sort();
    output.dedup_by_key(|benchmark| (benchmark.name.clone(), benchmark.kind));
    Ok(output)
}

enum BenchVariant {
    Runtime,
    Compilation,
}

impl BenchVariant {
    fn name(&self) -> &'static str {
        match self {
            BenchVariant::Runtime => "runtime",
            BenchVariant::Compilation => "compilation",
        }
    }
}

#[cfg(target_os = "linux")]
fn pick_benchmark(benchmark: Option<String>) -> (BenchVariant, Benchmark, BackendKind) {
    let benches = find_benchmarks().unwrap();
    let mut all = Vec::new();
    let mut found = Vec::new();
    for bench in &benches {
        for backend in bench.kind.matching_backends() {
            for variant in [BenchVariant::Runtime, BenchVariant::Compilation] {
                if matches!(variant, BenchVariant::Compilation) && !backend.is_compiled() {
                    continue;
                }

                let name = format!("{}/{}/{}", variant.name(), bench.name, backend.name());
                if let Some(ref benchmark) = benchmark {
                    if *benchmark == name {
                        println!("{} {}", benchmark, name);
                        found.push((variant, bench.clone(), backend));
                    }
                }
                all.push(name);
            }
        }
    }

    if found.is_empty() {
        if benchmark.is_some() {
            eprintln!("Fatal error: no matching benchmarks found!");
        }

        eprintln!("Available benchmarks:");

        all.sort();
        for name in all {
            eprintln!("  {name}");
        }

        std::process::exit(1);
    }

    if found.len() > 1 {
        eprintln!("Fatal error: multiple matching benchmarks found!");
        std::process::exit(1);
    }

    found.into_iter().next().unwrap()
}

#[cfg(target_os = "linux")]
struct Process {
    running: Arc<AtomicBool>,
    run_barrier: Arc<Barrier>,
    thread: std::thread::JoinHandle<()>,
    pid: u32,
    tid: u32,
    done_rx: std::sync::mpsc::Receiver<()>,
}

#[cfg(target_os = "linux")]
fn prepare_for_profiling<T>(
    iteration_limit: Option<usize>,
    initialize: impl FnOnce() -> (T, Option<u32>) + Send + 'static,
    mut run: impl FnMut(&mut T) + Send + 'static,
) -> Process
where
    T: 'static,
{
    let init_barrier = Arc::new(Barrier::new(2));
    let run_barrier = Arc::new(Barrier::new(2));
    let running = Arc::new(AtomicBool::new(false));
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);

    struct State {
        target: Option<(u32, u32)>,
    }

    let state = Arc::new(Mutex::new(State { target: None }));

    let thread = {
        let state = state.clone();
        let init_barrier = init_barrier.clone();
        let run_barrier = run_barrier.clone();
        let running = running.clone();
        std::thread::spawn(move || {
            let (mut benchmark_state, pid) = initialize();
            let (pid, tid) = if let Some(pid) = pid {
                log::info!("Child PID (external process): pid={pid}");
                (pid, pid)
            } else {
                let pid = unsafe { libc::getpid() };
                let tid = unsafe { libc::syscall(libc::SYS_gettid) };
                assert!(tid > 0);

                log::info!("Profiling self: pid={pid}, tid={tid}");
                (pid as u32, tid as u32)
            };

            state.lock().unwrap().target = Some((pid, tid));
            let iteration_limit = iteration_limit.unwrap_or(usize::MAX);

            init_barrier.wait();
            run_barrier.wait();
            for _ in 0..iteration_limit {
                if !running.load(Ordering::Relaxed) {
                    break;
                }

                run(&mut benchmark_state);
            }

            let _ = done_tx.send(());
        })
    };

    init_barrier.wait();
    core::mem::drop(init_barrier);

    let (pid, tid) = state.lock().unwrap().target.unwrap();
    Process {
        running,
        run_barrier,
        thread,
        pid,
        tid,
        done_rx,
    }
}

#[cfg(target_os = "linux")]
impl Process {
    fn start(&self) {
        self.running.store(true, Ordering::Relaxed);
        self.run_barrier.wait();
    }

    fn stop(self) {
        self.running.store(false, Ordering::Relaxed);
        self.thread.join().unwrap();
    }

    fn wait(self) {
        self.done_rx.recv().unwrap();
    }
}

#[derive(Parser, Debug)]
#[clap(version)]
enum Args {
    /// Runs the benchmarks with criterion.
    #[cfg(feature = "criterion")]
    Criterion { filter: Option<String> },

    /// Runs the benchmarks.
    Benchmark {
        /// The iteration limit of the benchmark.
        #[clap(long, short = 'i')]
        iteration_limit: Option<u64>,

        filter: Option<String>,
    },

    /// Runs `perf` for the given benchmark.
    #[cfg(target_os = "linux")]
    Perf {
        /// The benchmark to run.
        #[clap(long, short = 'b')]
        benchmark: Option<String>,

        /// The time limit, in seconds.
        #[clap(long, short = 't')]
        time_limit: Option<f64>,

        /// The iteration limit of the benchmark.
        #[clap(long, short = 'i')]
        iteration_limit: Option<usize>,

        /// The `perf` subcommand to run.
        command: String,

        /// Extra arguments to `perf`.
        perf_args: Vec<OsString>,
    },
}

fn main() {
    #[cfg(all(debug_assertions, not(miri)))]
    if std::env::var_os("TRUST_ME_BRO_I_KNOW_WHAT_I_AM_DOING").is_none() {
        // We have interpreters in the benchmark suite, so it's important to compile
        // with full optimizations and with full fat LTO to keep things fair.
        eprintln!("Not compiled with `--profile benchmark`; refusing to run! Please recompile and try again!");
        eprintln!("(...alternatively you can set the `TRUST_ME_BRO_I_KNOW_WHAT_I_AM_DOING` environment variable, if you know what you're doing...)");
        std::process::exit(1);
    }

    #[cfg(all(target_os = "linux", not(miri)))]
    crate::utils::restart_with_disabled_aslr().unwrap();

    #[cfg(feature = "env_logger")]
    env_logger::init();
    let args = Args::parse();

    match args {
        #[cfg(feature = "criterion")]
        Args::Criterion { filter } => {
            let benches = find_benchmarks().unwrap();
            let mut criterion = Criterion::default().sample_size(10).with_output_color(true);
            if let Some(filter) = filter {
                criterion = criterion.with_filter(filter);
            }

            criterion_main(&mut criterion, &benches);
            criterion.final_summary();
        }
        Args::Benchmark { iteration_limit, filter } => {
            let mut list = Vec::new();
            let benches = find_benchmarks().unwrap();
            for bench in &benches {
                for backend in bench.kind.matching_backends() {
                    for variant in [BenchVariant::Runtime, BenchVariant::Compilation] {
                        if matches!(variant, BenchVariant::Compilation) && !backend.is_compiled() {
                            continue;
                        }

                        let name = format!("{}/{}/{}", variant.name(), bench.name, backend.name());
                        if let Some(ref filter) = filter {
                            if !name.contains(filter) {
                                continue;
                            }
                        }
                        list.push((name, variant, bench, backend));
                    }
                }
            }

            for (name, variant, bench, backend) in list {
                use std::io::Write;
                let _ = write!(&mut std::io::stdout(), "{name}: ...");
                let _ = std::io::stdout().flush();

                let elapsed = match variant {
                    BenchVariant::Runtime => {
                        let (outer_count, inner_count) = if backend.is_slow() {
                            (iteration_limit.unwrap_or(1), SLOW_INNER_COUNT)
                        } else {
                            (iteration_limit.unwrap_or(12), FAST_INNER_COUNT)
                        };
                        benchmark_execution(outer_count, inner_count, backend, &bench.path) / outer_count as u32
                    }
                    BenchVariant::Compilation => {
                        let count = if cfg!(miri) { 1 } else { iteration_limit.unwrap_or(128) };
                        benchmark_compilation(count, backend, &bench.path) / count as u32
                    }
                };

                let elapsed = if elapsed.as_secs() > 0 {
                    format!("{:.03}s", elapsed.as_secs_f64())
                } else if elapsed.as_millis() > 9 {
                    format!("{}ms", elapsed.as_millis())
                } else if elapsed.as_micros() > 0 {
                    format!("{}us", elapsed.as_micros())
                } else {
                    format!("{}ns", elapsed.as_nanos())
                };

                let _ = writeln!(&mut std::io::stdout(), "\r{name}: {elapsed}");
            }
        }
        #[cfg(target_os = "linux")]
        Args::Perf {
            benchmark,
            mut time_limit,
            iteration_limit,
            command,
            perf_args,
        } => {
            let (variant, bench, backend) = pick_benchmark(benchmark);

            if time_limit.is_none() && iteration_limit.is_none() {
                time_limit = Some(5.0);
            }

            let process = match variant {
                BenchVariant::Runtime => prepare_for_profiling(
                    iteration_limit,
                    move || {
                        let mut engine = backend.create();
                        let blob = backend.load(&bench.path);
                        let module = backend.compile(&mut engine, &blob);
                        let mut instance = backend.spawn(&mut engine, &module);
                        backend.initialize(&mut instance);
                        let pid = backend.pid(&instance);
                        (instance, pid)
                    },
                    move |instance| {
                        backend.run(instance);
                    },
                ),
                BenchVariant::Compilation => prepare_for_profiling(
                    iteration_limit,
                    move || {
                        let engine = backend.create();
                        let blob = backend.load(&bench.path);
                        ((engine, blob), None)
                    },
                    move |(engine, blob)| {
                        backend.compile(engine, blob);
                    },
                ),
            };

            let mut cmd = Command::new("perf");
            let mut cmd = cmd
                .arg(&command)
                .arg(format!("--pid={}", process.pid))
                .arg(format!("--tid={}", process.tid));

            if command == "record" {
                cmd = cmd.arg("--freq=max");
            }

            for arg in perf_args {
                cmd = cmd.arg(arg);
            }

            let mut child = cmd.spawn().unwrap();
            std::thread::sleep(core::time::Duration::from_millis(5));
            process.start();

            if let Some(time_limit) = time_limit {
                std::thread::sleep(core::time::Duration::from_secs_f64(time_limit));
                process.stop();
            } else {
                process.wait();
            }

            unsafe {
                libc::kill(child.id() as _, libc::SIGINT);
            }

            child.wait().unwrap();
        }
    }
}
