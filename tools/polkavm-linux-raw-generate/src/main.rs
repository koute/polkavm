fn main() {
    let whitelist_var = [
        "__NR_.+",
        "__WALL",
        "__WCLONE",
        "__WNOTHREAD",
        "_LINUX_CAPABILITY_.+",
        "ARCH_.+",
        "AT_.+",
        "BPF_.+",
        "CLD_.+",
        "CLOCK_.+",
        "CLONE_.+",
        "F_.+",
        "FALLOC_.+",
        "FUTEX_.+",
        "MADV_.+",
        "MAP_.+",
        "MFD_.+",
        "MINSIGSTKSZ",
        "MREMAP_.+",
        "MS_.+",
        "O_.+",
        "P_.+",
        "PROT_.+",
        "RLIMIT_.+",
        "SA_.+",
        "SECBIT_.+",
        "SECCOMP_.+",
        "SIG.+",
        "WCONTINUED",
        "WEXITED",
        "WNOHANG",
        "WNOWAIT",
        "WSTOPPED",
        "E2BIG",
        "EACCES",
        "EAGAIN",
        "EBADF",
        "EBUSY",
        "ECHILD",
        "EDOM",
        "EEXIST",
        "EFAULT",
        "EFBIG",
        "EINTR",
        "EINVAL",
        "EIO",
        "EISDIR",
        "EMFILE",
        "EMLINK",
        "ENFILE",
        "ENODEV",
        "ENOENT",
        "ENOEXEC",
        "ENOMEM",
        "ENOSPC",
        "ENOTBLK",
        "ENOTDIR",
        "ENOTTY",
        "ENXIO",
        "EOPNOTSUPP",
        "EPERM",
        "EPIPE",
        "ERANGE",
        "EROFS",
        "ESPIPE",
        "ESRCH",
        "ETIMEDOUT",
        "ETOOMANYREFS",
        "ETXTBSY",
        "EXDEV",
        "_?UFFD.+",
        "_IOC.*",
        "IORING.+",
        "IOSQE.+",
        "FUTEX2.+",
        "PTRACE_.+",
    ]
    .join("|");

    let whitelist_type = [
        "__kernel_gid_t",
        "__kernel_off_t",
        "__kernel_uid_t",
        "__rlimit_resource",
        "__user_cap_data_struct",
        "__user_cap_header_struct",
        "cmsghdr",
        "iovec",
        "linux_dirent64",
        "msghdr",
        "rlimit",
        "rusage",
        "sigaction",
        "siginfo_t",
        "sigset_t",
        "timespec",
        "uffd_msg",
        "uffdio.+",
        "io_uring.+",
        "new_utsname",
    ]
    .join("|");

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    std::env::set_current_dir(root).unwrap();

    let bindings = bindgen::Builder::default()
        .use_core()
        .header(root.join("src").join("wrapper.h").canonicalize().unwrap().to_str().unwrap())
        .allowlist_var(whitelist_var)
        .allowlist_type(whitelist_type)
        .clang_arg("--target=x86_64-unknown-linux")
        .clang_arg("-DBITS_PER_LONG=(__SIZEOF_LONG__*__CHAR_BIT__)")
        .clang_arg("-nostdinc")
        .clang_arg("-I")
        .clang_arg(
            root.join("linux/linux-6.9.3-headers/include")
                .canonicalize()
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .clang_arg("-I")
        .clang_arg(root.join("linux/linux-6.9.3/include").canonicalize().unwrap().to_str().unwrap())
        .sort_semantically(true)
        .generate()
        .unwrap();

    let output_path = root.join("../../crates/polkavm-linux-raw/src/arch_amd64_bindings.rs");
    std::fs::write(&output_path, bindings.to_string()).unwrap();

    println!("Bindings written to {:?}!", output_path);
}
