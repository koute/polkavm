#!/usr/bin/ruby

require "json"

timestamp = nil
benches = {}
Dir["target/criterion/*/*/new"].each do |path|
    kind, bench, vm = JSON.parse(File.read(File.join(path, "benchmark.json")))["full_id"].split("/")
    if vm == "pvfexecutor"
        next # Not a production VM, so skip it.
    end

    estimates_path = File.join(path, "estimates.json")
    local_timestamp = File.mtime(estimates_path).getutc
    timestamp =
        if timestamp != nil
            [timestamp, local_timestamp].max
        else
            local_timestamp
        end

    result = JSON.parse(File.read(estimates_path))["mean"]

    time = result["point_estimate"]
    interval = [(result["confidence_interval"]["upper_bound"] - time).abs, (result["confidence_interval"]["lower_bound"] - time).abs].max
    benches[bench] ||= {}
    benches[bench][kind] ||= []
    benches[bench][kind] << [vm, time / 1_000_000_000.0, interval / 1_000_000_000.0]
end

def unit_to_mul unit
    if unit == "s"
        1.0
    elsif unit == "ms"
        1000.0
    elsif unit == "µs"
        1000000.0
    elsif unit == "ns"
        1000000000.0
    else
        raise unit
    end
end

def get_unit value
    if value >= 1.0
        "s"
    elsif value < 0.001
        "µs"
    else
        "ms"
    end
end

def fmt time, error
    unit = get_unit [time, error].max
    mul = unit_to_mul unit
    lhs = "%.03f%s" % [ time * mul, unit.rjust(2) ]
    lhs.rjust(9) + " ± " + ("%2.03f%s" % [ error * mul, unit ]).rjust(8)
end

def generate_table rows
    col_widths = rows.transpose.map { |xs| xs.map { |x| x.to_s.length }.max }
    rows = rows.map do |row|
        "| " + row.each_with_index.map do |x, i|
            if i == 0
                x.to_s.ljust( col_widths[i] )
            else
                x.to_s.rjust( col_widths[i] )
            end
        end.join(" | ") + " |"
    end
    (rows[0] + ("\n|-" + col_widths.map { |w| "-" * w }.join("-|-") + "-|\n") + rows[1..].join("\n")).strip
end

NAME_MAP = {
    "native" => "(bare metal)",
    "polkavm_compiler_no_gas" => "**PolkaVM (recompiler)**",
    "polkavm_compiler_sync_gas" => "PolkaVM (recompiler, sync gas)",
    "polkavm_compiler_async_gas" => "PolkaVM (recompiler, async gas)",
    "wasmer" => "Wasmer (singlepass)",
    "wasmtime_cranelift_default" => "Wasmtime (cranelift)",
    "wasmtime_cranelift_with_epoch" => "Wasmtime (cranelift, epoch interruption)",
    "wasmtime_cranelift_with_fuel" => "Wasmtime (cranelift, fuel metering)",
    "wasmtime_winch" => "Wasmtime (winch)",
    "wasmi_lazy" => "Wasmi (lazy)",
    "wasmi_lazy_translation" => "Wasmi (lazy translation)",
    "wasmi_eager" => "Wasmi (eager)",
    "solana_rbpf" => "Solana RBPF",
    "ckbvm_asm" => "CKB VM (ASM)",
    "ckbvm_non_asm" => "CKB VM (non-ASM)",
    "polkavm_interpreter" => "PolkaVM (interpreter)",
    "wasm3" => "Wasm3",

    "runtime" => "Execution time",
    "compilation" => "Compilation time",
    "oneshot" => "Oneshot execution",
}

if File.exist?("target/criterion/commit.txt")
    commit = File.read("target/criterion/commit.txt")
    commit_known = true
else
    commit = "master"
    commin_known = false
end

if File.exist?("target/criterion/cpu.txt")
    cpu = File.read("target/criterion/cpu.txt")
end

if File.exist?("target/criterion/platform.txt")
    platform = File.read("target/criterion/platform.txt")
end

PROGRAM_DESCRIPTIONS = {
    "pinky" => "This benchmark is a cycle-accurate NES emulator, running a real, homebrew NES game. ([source code](https://github.com/koute/polkavm/blob/#{commit}/guest-programs/bench-pinky/src/main.rs))",
    "prime-sieve" => "This benchmark is a prime sieve, searching for subsequent prime numbers. ([source code](https://github.com/koute/polkavm/tree/#{commit}/guest-programs/bench-prime-sieve))",
    "minimal" => "This benchmark is a tiny, minimal program which doesn't do much work; it just increments a global variable and returns immediately. It is a good test case for measuring constant-time overhead. ([source code](https://github.com/koute/polkavm/blob/#{commit}/guest-programs/bench-minimal/src/main.rs))",
}

KIND_DESCRIPTIONS = {
    "oneshot" => "These benchmarks measure the end-to-end time that it takes to run the program a single time, including compilation and initialization.",
    "runtime" => "These benchmarks measure the execution time of the benchmark, *without* the time it takes to compile or initialize it.",
    "compilation" => "These benchmarks measure the time it takes to compile a given program by the VM.",
}

markdown = ""

PROGRAM_DESCRIPTIONS.each do |bench, program_description|
    kinds = benches[bench]
    markdown += "# Benchmark: #{bench}\n\n"
    markdown += program_description + "\n\n"
    ["oneshot", "runtime", "compilation"].each do |kind|
        results = kinds[kind]
        next if results == nil
        markdown += "## #{NAME_MAP[kind] || kind} (for #{bench})\n\n"
        markdown += KIND_DESCRIPTIONS[kind] + "\n\n"
        table = [["VM", "Time", "vs fastest"]]
        results = results.sort_by { |xs| xs[1] }
        baseline = results[0][1]
        results.each do |vm, time, error|
            table << [NAME_MAP[vm] || vm, fmt(time, error), "%.02fx" % [time / baseline]]
        end
        markdown += generate_table(table)
        markdown += "\n\n"
    end
    markdown += "\n"
end

markdown += "-" * 75 + "\n\n"
markdown += "# Supplemental information\n\n"
timestamp = timestamp.strftime("%Y-%m-%y %H:%M:%S UTC")

if cpu != nil
    markdown += "CPU: #{cpu}\n\n"
end

if platform != nil
    markdown += "Platform: #{platform}\n\n"
end

if commit_known
    markdown += "Commit: [#{commit}](https://github.com/koute/polkavm/tree/#{commit})\n\n"
end

markdown += "Timestamp: #{timestamp}\n\n"

if commit_known
    markdown +="-" * 75 + "\n\n"
    markdown += "# Replication\n\n"

    markdown += "You can replicate these benchmarks as follows:\n\n"
    markdown += "```\n"
    markdown += "$ git clone https://github.com/koute/polkavm.git\n"
    markdown += "$ cd polkavm\n"
    markdown += "$ git checkout #{commit}\n"
    markdown += "$ cd tools/benchtool\n"
    markdown += "$ ./01-build-benchmarks.sh\n"
    markdown += "$ ./02-run-benchmarks.rb\n"
    markdown += "$ ./03-analyze-benchmarks.rb\n"
    markdown += "```\n\n"
    markdown +=
        "Only running the benchmarks on Linux is officially supported.\n\n" +
        "WARNING: The `02-run-benchmarks.rb` script uses a couple of system-level tricks to make benchmarking more consistent " +
        "and requires 'sudo' and 'schedtool' to be installed. If you're uncomfortable with that or if you're running a non-Linux OS " +
        "you can also run the benchmarks with `cargo run --release` instead.\n\n"

end

if ARGV.include? "--update-markdown"
    File.write("../../BENCHMARKS.md", markdown)
else
    puts markdown
end
