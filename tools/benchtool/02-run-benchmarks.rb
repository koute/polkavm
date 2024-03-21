#!/usr/bin/ruby

require "shellwords"

$errors_are_fatal = true

def sudo_write(contents, path)
    system "echo #{contents.to_s.shellescape} | sudo tee #{path.shellescape} > /dev/null"
    if $?.exitstatus != 0
        STDERR.puts "ERROR: failed to write to '#{path}'"
        if $errors_are_fatal
            STDERR.puts "Aborting..."
            exit 1
        end
    end
end

def sudo_run(command)
    system "sudo #{command}"
    if $?.exitstatus != 0
        STDERR.puts "ERROR: command failed: #{command}"
        if $errors_are_fatal
            STDERR.puts "Aborting..."
            exit 1
        end
    end
end

BENCHMARK_KINDS = [
    "runtime",
    "compilation",
    "oneshot",
]

BENCHMARK_PROGRAMS = [
    "pinky",
    "prime-sieve",
    "minimal",
]

BENCHMARK_VMS = [
    "ckbvm_asm",
    "ckbvm_non_asm",
    "native",
    "polkavm_compiler_no_gas",
    "polkavm_compiler_async_gas",
    "polkavm_compiler_sync_gas",
    "polkavm_interpreter",
    "solana_rbpf",
    "wasm3",
    "wasmer",
    "wasmi_eager",
    "wasmi_lazy",
    "wasmi_lazy_translation",
    "wasmtime_cranelift_default",
    "wasmtime_cranelift_with_fuel",
    "wasmtime_cranelift_with_epoch",
    "wasmtime_winch",
    "wazero",
]

if File.exist? "target/criterion"
    unless ARGV.include? "--keep-old-results"
        STDERR.puts "ERROR: 'target/criterion' directory exists! Either delete it or pass '--keep-old-results'"
        STDERR.puts "(...in which case already existing results will NOT be regenerated!)"
        exit 1
    end
end

system "cargo build --release --features ckb-vm"
raise "failed to build benchtool" unless $?.exitstatus == 0

original_governor = File.read("/sys/devices/system/cpu/cpu1/cpufreq/scaling_governor").strip
original_numa_writeback = File.read("/sys/bus/workqueue/devices/writeback/numa").strip
original_sched_rt = File.read("/proc/sys/kernel/sched_rt_runtime_us").strip
original_watchdog = File.read("/proc/sys/kernel/watchdog").strip
original_stat_interval = File.read("/proc/sys/vm/stat_interval").strip

begin
    system "sync"

    STDERR.puts "Disabling turbo boost..."
    sudo_write "0", "/sys/devices/system/cpu/cpufreq/boost"
    raise "ERROR: failed to disable turbo boost" if $?.exitstatus != 0

    STDERR.puts "Applying misc. tweaks..."
    sudo_write "0", "/sys/bus/workqueue/devices/writeback/numa"
    sudo_write "-1", "/proc/sys/kernel/sched_rt_runtime_us"
    sudo_write "0", "/proc/sys/kernel/watchdog"
    sudo_write "1000", "/proc/sys/vm/stat_interval"

    STDERR.puts "Tweaking CPU masks..."
    sudo_write "1", "/sys/devices/virtual/workqueue/cpumask"
    sudo_write "1", "/sys/bus/workqueue/devices/writeback/cpumask"
    sudo_write "1", "/proc/irq/default_smp_affinity"

    STDERR.puts "Changing the scaling governor to 'performance'..."
    sudo_write "performance", "/sys/devices/system/cpu/cpu1/cpufreq/scaling_governor"
    raise "ERROR: failed to change the scaling governor for CPU1" if $?.exitstatus != 0
    sudo_write "performance", "/sys/devices/system/cpu/cpu2/cpufreq/scaling_governor"
    raise "ERROR: failed to change the scaling governor for CPU2" if $?.exitstatus != 0

    STDERR.puts "Setting up cgroups..."
    sudo_run "mkdir /sys/fs/cgroup/benchtool"
    sudo_write "+cpuset", "/sys/fs/cgroup/benchtool/cgroup.subtree_control"
    sudo_write "1-2", "/sys/fs/cgroup/benchtool/cpuset.cpus"
    sudo_write "0,3-127", "/sys/fs/cgroup/user.slice/cpuset.cpus"
    sudo_write "0,3-127", "/sys/fs/cgroup/system.slice/cpuset.cpus"

    STDERR.puts "Launching child process..."
    rx, tx = IO.pipe
    child = Kernel.fork do
        tx.close
        rx.read # Wait for the parent process to add us to the cgroup.

        STDERR.puts "Running benchmarks..."

        cpu = File.read("/proc/cpuinfo").scan(/model name\s*:\s*(.+)/)[0][0]
        commit = `git rev-parse HEAD`.strip
        File.write("target/criterion/cpu.txt", cpu)
        File.write("target/criterion/commit.txt", commit)
        File.write("target/criterion/platform.txt", RUBY_PLATFORM)

        BENCHMARK_KINDS.each do |kind|
            BENCHMARK_PROGRAMS.each do |program|
                BENCHMARK_VMS.each do |vm|
                    next if File.exist? "target/criterion/#{kind}_#{program}/#{vm}/new/estimates.json"
                    system "../../target/release/benchtool criterion #{kind}/#{program}/#{vm}"
                end
            end
        end
        exit 0
    end

    STDERR.puts "Adding child to cgroup and setting its priority..."
    sudo_write child, "/sys/fs/cgroup/benchtool/cgroup.procs"
    sudo_run "schedtool -F -p 99 -n -20 #{child}"

    rx.close
    tx.close
    Process.wait child

    ensure
        $errors_are_fatal = false

        STDERR.puts "Restoring turbo boost..."
        sudo_write "1", "/sys/devices/system/cpu/cpufreq/boost"

        STDERR.puts "Restoring the scaling governor to '#{original_governor}'..."
        sudo_write original_governor, "/sys/devices/system/cpu/cpu1/cpufreq/scaling_governor"
        sudo_write original_governor, "/sys/devices/system/cpu/cpu2/cpufreq/scaling_governor"

        STDERR.puts "Restoring cgroups..."
        sudo_write "0-127", "/sys/fs/cgroup/user.slice/cpuset.cpus"
        sudo_write "0-127", "/sys/fs/cgroup/system.slice/cpuset.cpus"
        sudo_run "rmdir /sys/fs/cgroup/benchtool"

        STDERR.puts "Restoring misc. tweaks..."
        sudo_write "ffffffff,ffffffff,ffffffff,ffffffff", "/sys/devices/virtual/workqueue/cpumask"
        sudo_write "ffffffff,ffffffff,ffffffff,ffffffff", "/sys/bus/workqueue/devices/writeback/cpumask"
        sudo_write "ffffffff,ffffffff,ffffffff,ffffffff", "/proc/irq/default_smp_affinity"
        sudo_write original_numa_writeback, "/sys/bus/workqueue/devices/writeback/numa"
        sudo_write original_sched_rt, "/proc/sys/kernel/sched_rt_runtime_us"
        sudo_write original_watchdog, "/proc/sys/kernel/watchdog"
        sudo_write original_stat_interval, "/proc/sys/vm/stat_interval"

        STDERR.puts "Original state restored!"
end
