use clap::Parser;
use core::time::Duration;
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

use crate::backend::{Backend, CreateArgs};

const FAST_INNER_COUNT: u32 = 32;
const SLOW_INNER_COUNT: u32 = 1;

fn benchmark_execution<T: Backend>(
    engine_cache: &mut Option<T::Engine>,
    outer_count: u64,
    inner_count: u32,
    backend: T,
    path: &Path,
    size: Option<u64>,
) -> core::time::Duration {
    let mut total_elapsed = core::time::Duration::new(0, 0);
    let mut engine = engine_cache
        .take()
        .unwrap_or_else(|| backend.create(CreateArgs { is_compile_only: false }));
    let blob = backend.load(path);
    let module = backend.compile(&mut engine, &blob);
    for _ in 0..outer_count {
        let mut instance = backend.spawn(&mut engine, &module);
        backend.initialize(&mut instance);
        if let Some(size) = size {
            assert!(backend.set_size(&mut instance, size));
        }
        let start = std::time::Instant::now();
        for _ in 0..inner_count {
            backend.run(&mut instance);
        }
        total_elapsed += start.elapsed();
    }

    let elapsed = total_elapsed / inner_count;
    *engine_cache = Some(engine);
    elapsed
}

fn benchmark_compilation<T: Backend>(engine_cache: &mut Option<T::Engine>, count: u64, backend: T, path: &Path) -> core::time::Duration {
    let mut engine = engine_cache
        .take()
        .unwrap_or_else(|| backend.create(CreateArgs { is_compile_only: true }));
    let blob = backend.load(path);
    let start = std::time::Instant::now();
    for _ in 0..count {
        backend.compile(&mut engine, &blob);
    }
    let elapsed = start.elapsed();
    *engine_cache = Some(engine);
    elapsed
}

fn benchmark_oneshot<T: Backend>(
    engine_cache: &mut Option<T::Engine>,
    count: u64,
    backend: T,
    path: &Path,
    size: Option<u64>,
) -> core::time::Duration {
    let mut engine = engine_cache
        .take()
        .unwrap_or_else(|| backend.create(CreateArgs { is_compile_only: false }));
    let blob = backend.load(path);
    {
        let module = backend.compile(&mut engine, &blob);
        let mut instance = backend.spawn(&mut engine, &module);
        backend.initialize(&mut instance);
        if let Some(size) = size {
            assert!(backend.set_size(&mut instance, size));
        }
        backend.run(&mut instance);
    }

    let start = std::time::Instant::now();
    for _ in 0..count {
        let module = backend.compile(&mut engine, &blob);
        let mut instance = backend.spawn(&mut engine, &module);
        backend.initialize(&mut instance);
        if let Some(size) = size {
            assert!(backend.set_size(&mut instance, size));
        }
        backend.run(&mut instance);
    }
    let elapsed = start.elapsed();
    *engine_cache = Some(engine);
    elapsed
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
                group.bench_function(backend.name(), |b| {
                    b.iter_custom(|count| benchmark_execution(&mut None, count, FAST_INNER_COUNT, backend, &bench.path, None));
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
                    b.iter_custom(|count| benchmark_compilation(&mut None, count, backend, &bench.path));
                });
            }
        }
        group.finish();
    }

    for (name, variants) in &by_name {
        let mut group = c.benchmark_group(format!("oneshot/{}", name));
        for bench in variants {
            for backend in bench.kind.matching_backends() {
                group.bench_function(backend.name(), |b| {
                    b.iter_custom(|count| benchmark_oneshot(&mut None, count, backend, &bench.path, None));
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
    PolkaVM32,
    PolkaVM64,
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
                let Some(target) = target else { continue };
                if target == "riscv64emac-unknown-none-polkavm" {
                    BenchmarkKind::PolkaVM64
                } else if target == "riscv32emac-unknown-none-polkavm" {
                    BenchmarkKind::PolkaVM32
                } else {
                    eprintln!("WARNING: found unrecognized .polkavm artifact: {path:?} (target = {target:?})");
                    continue;
                }
            } else if extension == "so" {
                if target.as_ref().map_or(false, |target| *target == "sbf-solana-solana") {
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
    let mut roots = vec![Path::new(env!("CARGO_MANIFEST_DIR")).join("../../guest-programs/target")];
    if let Ok(root) = std::env::var("CARGO_TARGET_DIR") {
        roots.push(PathBuf::from(root));
    }

    let mut paths = vec![PathBuf::from(".")];
    for root in roots {
        paths.extend([
            root.join("riscv32emac-unknown-none-polkavm/release"),
            root.join("riscv64emac-unknown-none-polkavm/release"),
            root.join("riscv64imac-unknown-none-elf/release"),
            root.join("wasm32-unknown-unknown/release"),
            root.join("sbf-solana-solana/release"),
            #[cfg(target_arch = "x86_64")]
            root.join("x86_64-unknown-linux-gnu/release"),
            #[cfg(target_arch = "x86")]
            root.join("i686-unknown-linux-gnu/release"),
        ]);
    }

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

/// Whether the benchmark's artifact exports `benchmark_set_size`.
///
/// The export's name appears verbatim in every artifact format we produce
/// (.polkavm export table, ELF dynsym, wasm export section), so a plain byte
/// scan is sufficient.
fn benchmark_supports_set_size(benchmark: &Benchmark) -> bool {
    const SET_SIZE: &[u8] = b"benchmark_set_size";
    std::fs::read(&benchmark.path).is_ok_and(|bytes| bytes.windows(SET_SIZE.len()).any(|window| window == SET_SIZE))
}

#[derive(Copy, Clone)]
enum BenchVariant {
    Runtime,
    Compilation,
    Oneshot,
}

impl BenchVariant {
    fn name(&self) -> &'static str {
        match self {
            BenchVariant::Runtime => "runtime",
            BenchVariant::Compilation => "compilation",
            BenchVariant::Oneshot => "oneshot",
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
            for variant in [BenchVariant::Runtime, BenchVariant::Compilation, BenchVariant::Oneshot] {
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

        /// Runs the benchmark forever, periodically outputing the measurements.
        #[clap(long)]
        forever: bool,

        /// Run with ASLR enabled.
        #[clap(long)]
        aslr: bool,

        /// Comma-separated input sizes, in bytes; passed to benchmarks that
        /// export `benchmark_set_size` (others run unparameterized as usual).
        #[clap(long)]
        size: Option<String>,

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

        /// Input size, in bytes; passed to the benchmark's
        /// `benchmark_set_size` export (must be supported).
        #[clap(long)]
        size: Option<u64>,

        /// The `perf` subcommand to run.
        command: String,

        /// Extra arguments to `perf`.
        perf_args: Vec<OsString>,
    },

    /// Benchmarks PolkaVM's memset.
    BenchMemset,

    /// Benchmarks ecalli overhead.
    BenchEcalli {
        #[clap(long)]
        interpreter: bool,
    },

    /// Benchmarks memory access overhead.
    BenchMemoryAccess {
        #[clap(long)]
        interpreter: bool,

        #[clap(long)]
        dynamic_paging: bool,

        #[clap(long)]
        store: bool,
    },
}

fn disable_aslr() {
    #[cfg(all(target_os = "linux", not(miri)))]
    crate::utils::restart_with_disabled_aslr().unwrap();
}

fn format_time_with_div(elapsed: Duration, divisor: u32) -> String {
    let e = elapsed / divisor;
    let s = e.as_secs_f64();
    if e.as_secs() > 0 {
        format!("{:.03}s", s)
    } else if e.as_millis() > 9 {
        format!("{:.02}ms", s * 1000.0)
    } else if e.as_micros() > 9 {
        format!("{:.02}us", s * 1000000.0)
    } else {
        let p = (elapsed.as_nanos() * 1000) / u128::from(divisor);
        if e.as_nanos() > 9 {
            format!("{:.02}ns", (p as f32) / 1000.0)
        } else {
            format!("{}ps", p)
        }
    }
}

fn format_time(elapsed: Duration) -> String {
    format_time_with_div(elapsed, 1)
}

fn main() {
    #[cfg(all(debug_assertions, not(miri)))]
    if std::env::var_os("TRUST_ME_BRO_I_KNOW_WHAT_I_AM_DOING").is_none() {
        // We have interpreters in the benchmark suite, so it's important to compile
        // with full optimizations and with full fat LTO to keep things fair.
        eprintln!("Not compiled with `--release`; refusing to run! Please recompile and try again!");
        eprintln!("(...alternatively you can set the `TRUST_ME_BRO_I_KNOW_WHAT_I_AM_DOING` environment variable, if you know what you're doing...)");
        std::process::exit(1);
    }

    #[cfg(feature = "env_logger")]
    env_logger::init();
    let args = Args::parse();

    match args {
        #[cfg(feature = "criterion")]
        Args::Criterion { filter } => {
            disable_aslr();

            let benches = find_benchmarks().unwrap();
            let mut criterion = Criterion::default().sample_size(10).with_output_color(true);
            if let Some(filter) = filter {
                criterion = criterion.with_filter(filter);
            }

            criterion_main(&mut criterion, &benches);
            criterion.final_summary();
        }
        Args::Benchmark {
            iteration_limit,
            filter,
            forever,
            aslr,
            size,
        } => {
            if !aslr {
                disable_aslr();
            }

            let sizes: Option<Vec<u64>> = size.map(|size| {
                size.split(',')
                    .map(|value| value.trim().parse().expect("invalid --size entry"))
                    .collect()
            });

            let mut list = Vec::new();
            let benches = find_benchmarks().unwrap();
            for bench in &benches {
                // Sizes apply only to benchmarks that export `benchmark_set_size`;
                // everything else runs unparameterized, exactly as without --size.
                let bench_sizes: Vec<Option<u64>> = match sizes {
                    Some(ref sizes) if benchmark_supports_set_size(bench) => sizes.iter().copied().map(Some).collect(),
                    _ => vec![None],
                };

                for backend in bench.kind.matching_backends() {
                    for variant in [BenchVariant::Runtime, BenchVariant::Compilation, BenchVariant::Oneshot] {
                        if matches!(variant, BenchVariant::Compilation) && !backend.is_compiled() {
                            continue;
                        }

                        // Compilation is size-independent; run it once.
                        let variant_sizes: &[Option<u64>] = if matches!(variant, BenchVariant::Compilation) {
                            &[None]
                        } else {
                            &bench_sizes
                        };

                        for &bench_size in variant_sizes {
                            // Skip sized entries on backends that cannot call the export.
                            if bench_size.is_some() && !backend.supports_set_size() {
                                continue;
                            }

                            let name = match bench_size {
                                Some(bench_size) => format!("{}/{}/{}/{}", variant.name(), bench.name, backend.name(), bench_size),
                                None => format!("{}/{}/{}", variant.name(), bench.name, backend.name()),
                            };
                            if let Some(ref filter) = filter {
                                if !name.contains(filter) {
                                    continue;
                                }
                            }
                            list.push((name, variant, bench, backend, bench_size));
                        }
                    }
                }
            }

            if list.is_empty() {
                eprintln!("No benchmarks found; exiting!");
                std::process::exit(1);
            }

            struct Stats {
                min: Duration,
                max: Duration,
                sum: Duration,
                count: u32,
                samples: Vec<Duration>,
            }

            let mut stats_for_bench = Vec::new();
            let mut engine_cache = Vec::new();
            for _ in 0..list.len() {
                engine_cache.push(None);
            }

            loop {
                let is_initial_run = stats_for_bench.is_empty();
                for (nth_bench, &(ref name, variant, bench, backend, bench_size)) in list.iter().enumerate() {
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
                            benchmark_execution(
                                &mut engine_cache[nth_bench],
                                outer_count,
                                inner_count,
                                backend,
                                &bench.path,
                                bench_size,
                            ) / outer_count as u32
                        }
                        BenchVariant::Compilation => {
                            let count = if cfg!(miri) { 1 } else { iteration_limit.unwrap_or(128) };
                            benchmark_compilation(&mut engine_cache[nth_bench], count, backend, &bench.path) / count as u32
                        }
                        BenchVariant::Oneshot => {
                            let count = iteration_limit.unwrap_or(10);
                            benchmark_oneshot(&mut engine_cache[nth_bench], count, backend, &bench.path, bench_size) / count as u32
                        }
                    };

                    if !forever {
                        engine_cache[nth_bench].take();
                    }

                    if is_initial_run {
                        let mut samples = vec![elapsed];
                        samples.reserve(100);
                        stats_for_bench.push(Stats {
                            min: elapsed,
                            max: elapsed,
                            sum: elapsed,
                            count: 1,
                            samples,
                        });
                    } else {
                        stats_for_bench[nth_bench].min = core::cmp::min(stats_for_bench[nth_bench].min, elapsed);
                        stats_for_bench[nth_bench].max = core::cmp::max(stats_for_bench[nth_bench].max, elapsed);
                        stats_for_bench[nth_bench].sum += elapsed;
                        stats_for_bench[nth_bench].count += 1;
                        stats_for_bench[nth_bench].samples.push(elapsed);
                        while stats_for_bench[nth_bench].samples.len() > 100 {
                            stats_for_bench[nth_bench].samples.pop();
                        }
                        stats_for_bench[nth_bench].samples.sort_unstable();
                    }

                    fn median(xs: &[Duration]) -> Duration {
                        if xs.len() % 2 == 1 {
                            xs[xs.len() / 2]
                        } else {
                            let mid_right = xs.len() / 2;
                            let mid_left = mid_right - 1;
                            (xs[mid_left] + xs[mid_right]) / 2
                        }
                    }

                    if is_initial_run {
                        let _ = writeln!(&mut std::io::stdout(), "\r{name}: {}", format_time(elapsed));
                    } else {
                        let stats = &stats_for_bench[nth_bench];
                        let avg = stats.sum / stats.count;
                        let med = median(&stats.samples);
                        let _ = writeln!(
                            &mut std::io::stdout(),
                            "\r{name}: {} (min={} max={} avg={} med={})",
                            format_time(elapsed),
                            format_time(stats.min),
                            format_time(stats.max),
                            format_time(avg),
                            format_time(med)
                        );
                    }
                }

                if !forever {
                    break;
                }
            }
        }
        #[cfg(target_os = "linux")]
        Args::Perf {
            benchmark,
            mut time_limit,
            iteration_limit,
            size,
            command,
            perf_args,
        } => {
            disable_aslr();

            let (variant, bench, backend) = pick_benchmark(benchmark);

            if time_limit.is_none() && iteration_limit.is_none() {
                time_limit = Some(5.0);
            }

            let process = match variant {
                BenchVariant::Runtime => prepare_for_profiling(
                    iteration_limit,
                    move || {
                        let mut engine = backend.create(CreateArgs { is_compile_only: false });
                        let blob = backend.load(&bench.path);
                        let module = backend.compile(&mut engine, &blob);
                        let mut instance = backend.spawn(&mut engine, &module);
                        backend.initialize(&mut instance);
                        if let Some(size) = size {
                            assert!(
                                backend.set_size(&mut instance, size),
                                "this benchmark/backend does not support --size"
                            );
                        }
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
                        let engine = backend.create(CreateArgs { is_compile_only: true });
                        let blob = backend.load(&bench.path);
                        ((engine, blob), None)
                    },
                    move |(engine, blob)| {
                        backend.compile(engine, blob);
                    },
                ),
                BenchVariant::Oneshot => prepare_for_profiling(
                    iteration_limit,
                    move || {
                        let engine = backend.create(CreateArgs { is_compile_only: false });
                        let blob = backend.load(&bench.path);
                        ((engine, blob), None)
                    },
                    move |(engine, blob)| {
                        let module = backend.compile(engine, blob);
                        let mut instance = backend.spawn(engine, &module);
                        backend.initialize(&mut instance);
                        if let Some(size) = size {
                            assert!(
                                backend.set_size(&mut instance, size),
                                "this benchmark/backend does not support --size"
                            );
                        }
                        backend.run(&mut instance);
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
        Args::BenchMemset => {
            let config = polkavm::Config::from_env().unwrap();
            let engine = polkavm::Engine::new(&config).unwrap();
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../guest-programs/target/riscv64emac-unknown-none-polkavm/release/bench-memset.polkavm");
            let raw_blob = std::fs::read(path).unwrap();
            let blob = polkavm::ProgramBlob::parse(raw_blob.into()).unwrap();
            let mut config = polkavm::ModuleConfig::default();
            config.set_gas_metering(Some(polkavm::GasMeteringKind::Sync));
            let module = polkavm::Module::from_blob(&engine, &config, blob).unwrap();
            let ext_initialize = module.exports().find(|export| export == "initialize").unwrap().program_counter();
            let ext_run_accelerated = module
                .exports()
                .find(|export| export == "benchmark_custom_accelerated")
                .unwrap()
                .program_counter();
            let ext_run_naive = module
                .exports()
                .find(|export| export == "benchmark_custom_naive")
                .unwrap()
                .program_counter();
            let ext_run_compiler_builtins = module
                .exports()
                .find(|export| export == "benchmark_custom_compiler_builtins")
                .unwrap()
                .program_counter();
            let linker = polkavm::Linker::<()>::new();
            let instance_pre = linker.instantiate_pre(&module).unwrap();
            let mut instance = instance_pre.instantiate().unwrap();
            instance.set_gas(polkavm::Gas::MAX);
            instance.call_typed(&mut (), ext_initialize, ()).unwrap();
            let sizes = [
                (1, 1024 * 1024 * 4),
                (256, 1024 * 512),
                (512, 1024 * 256),
                (4096, 1024 * 4),
                (1024 * 64, 1024),
                (1024 * 1024 * 2, 256),
            ];

            for (size, times) in sizes {
                for (offset, offset_name) in [(0, "aligned"), (1, "unaligned")] {
                    for (kind, kind_name) in [
                        (ext_run_accelerated, "accelerated"),
                        (ext_run_compiler_builtins, "compiler_builtins"),
                        (ext_run_naive, "naive"),
                    ] {
                        instance.call_typed(&mut (), kind, (offset, size, times)).unwrap();

                        let timestamp = std::time::Instant::now();
                        instance.call_typed(&mut (), kind, (offset, size, times)).unwrap();
                        println!(
                            "{kind_name:<18} {size:<8} {offset_name:<10}: {}",
                            format_time_with_div(timestamp.elapsed(), times)
                        );
                    }
                }
            }
        }
        Args::BenchEcalli { interpreter } => {
            use polkavm_common::program::{asm, InstructionSetKind, ProgramBlob};
            let mut builder = polkavm_common::writer::ProgramBlobBuilder::new(InstructionSetKind::JamV1);
            builder.add_export_by_basic_block(0, b"main");
            builder.set_code(&[asm::ecalli(0), asm::jump(0)], &[]);
            let blob = ProgramBlob::parse(builder.into_vec().unwrap().into()).unwrap();
            let mut config = polkavm::Config::from_env().unwrap();
            if interpreter {
                config.set_backend(Some(polkavm::BackendKind::Interpreter));
            } else {
                config.set_backend(Some(polkavm::BackendKind::Compiler));
            }

            let times = 1000000;
            let engine = polkavm::Engine::new(&config).unwrap();
            let module = polkavm::Module::from_blob(&engine, &polkavm::ModuleConfig::default(), blob).unwrap();
            let mut instance = module.instantiate().unwrap();
            instance.set_next_program_counter(polkavm::ProgramCounter(0));

            for _ in 0..50 {
                let timestamp = std::time::Instant::now();
                for _ in 0..times {
                    assert!(matches!(instance.run().unwrap(), polkavm::InterruptKind::Ecalli(0)));
                }

                println!("{}", format_time_with_div(timestamp.elapsed(), times));
            }
        }
        Args::BenchMemoryAccess {
            interpreter,
            dynamic_paging,
            store,
        } => {
            use polkavm::{MemoryProtection, Reg};
            use polkavm_common::abi::MemoryMapBuilder;
            use polkavm_common::program::{asm, InstructionSetKind, ProgramBlob};

            let times = if interpreter { 1000000 } else { 20000000 };

            let memory_map = MemoryMapBuilder::new(4096).rw_data_size(4096).build().unwrap();

            let mut builder = polkavm_common::writer::ProgramBlobBuilder::new(InstructionSetKind::JamV1);
            builder.add_export_by_basic_block(0, b"main");
            builder.set_rw_data_size(4096 * 64);
            builder.set_stack_size(4096);
            builder.set_code(
                &[
                    if store {
                        asm::store_u64(Reg::A1, memory_map.rw_data_address().try_into().unwrap())
                    } else {
                        asm::load_u64(Reg::A0, memory_map.rw_data_address().try_into().unwrap())
                    },
                    asm::add_imm_64(Reg::A1, Reg::A1, 1),
                    asm::branch_less_unsigned_imm(Reg::A1, times, 0),
                    asm::ret(),
                ],
                &[],
            );
            let blob = ProgramBlob::parse(builder.into_vec().unwrap().into()).unwrap();
            let mut config = polkavm::Config::from_env().unwrap();
            if interpreter {
                config.set_backend(Some(polkavm::BackendKind::Interpreter));
            } else {
                config.set_backend(Some(polkavm::BackendKind::Compiler));
            }
            config.set_allow_dynamic_paging(dynamic_paging);

            let engine = polkavm::Engine::new(&config).unwrap();
            let mut module_config = polkavm::ModuleConfig::default();
            module_config.set_dynamic_paging(dynamic_paging);
            let module = polkavm::Module::from_blob(&engine, &module_config, blob).unwrap();
            let mut instance = module.instantiate().unwrap();
            instance.set_reg(Reg::RA, polkavm::RETURN_TO_HOST);

            if dynamic_paging {
                instance
                    .zero_memory_with_memory_protection(memory_map.stack_address_low(), 4096, MemoryProtection::ReadWrite)
                    .unwrap();

                for n in (0..64).step_by(2) {
                    let address = memory_map.rw_data_address() + 4096 * n;

                    instance
                        .zero_memory_with_memory_protection(address, 4096, MemoryProtection::ReadWrite)
                        .unwrap();

                    instance.write_u64(address, u64::from(n)).unwrap();
                }
            } else {
                instance.write_u64(memory_map.rw_data_address(), 0).unwrap();
            }

            for _ in 0..50 {
                instance.set_next_program_counter(polkavm::ProgramCounter(0));
                instance.set_reg(Reg::A1, 0);
                let timestamp = std::time::Instant::now();
                assert!(matches!(instance.run().unwrap(), polkavm::InterruptKind::Finished));
                println!("{}", format_time_with_div(timestamp.elapsed(), times.try_into().unwrap()));
            }
        }
    }
}
