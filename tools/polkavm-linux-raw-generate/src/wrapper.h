#include <asm/signal.h>
#include <asm/unistd_64.h>
#include <asm/prctl.h>
#include <asm/ioctl.h>
#include <asm/ptrace.h>
#include <asm/ptrace-abi.h>

#include <asm-generic/resource.h>
#include <asm-generic/fcntl.h>
#include <asm-generic/mman-common.h>
#include <asm-generic/signal-defs.h>
#include <asm-generic/siginfo.h>
#include <asm-generic/posix_types.h>
#include <asm-generic/errno.h>

#include <linux/futex.h>
#include <linux/seccomp.h>
#include <linux/securebits.h>
#include <linux/bpf_common.h>
#include <linux/sched.h>
#include <linux/auxvec.h>
#include <linux/memfd.h>
#include <linux/mount.h>
#include <linux/fcntl.h>
#include <linux/mman.h>
#include <linux/time.h>
#include <linux/uio.h>
#include <linux/resource.h>
#include <linux/types.h>
#include <linux/capability.h>
#include <linux/wait.h>
#include <linux/falloc.h>
#include <linux/userfaultfd.h>
#include <linux/io_uring.h>
#include <linux/utsname.h>
#include <linux/ptrace.h>

#define u64 __u64
#define s64 __s64
#include <linux/dirent.h>
