use crate::error::{bail, Error};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum BackendKind {
    Compiler,
    Interpreter,
}

impl core::fmt::Display for BackendKind {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        let name = match self {
            BackendKind::Compiler => "compiler",
            BackendKind::Interpreter => "interpreter",
        };

        fmt.write_str(name)
    }
}

impl BackendKind {
    #[cfg(feature = "std")]
    fn from_os_str(s: &std::ffi::OsStr) -> Result<Option<BackendKind>, Error> {
        if s == "auto" {
            Ok(None)
        } else if s == "interpreter" {
            Ok(Some(BackendKind::Interpreter))
        } else if s == "compiler" {
            Ok(Some(BackendKind::Compiler))
        } else {
            Err(Error::from_static_str(
                "invalid value of POLKAVM_BACKEND; supported values are: 'interpreter', 'compiler'",
            ))
        }
    }
}

impl BackendKind {
    pub fn is_supported(self) -> bool {
        match self {
            BackendKind::Interpreter => true,
            BackendKind::Compiler => if_compiler_is_supported! {
                { true } else { false }
            },
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SandboxKind {
    Linux,
    Generic,
}

impl core::fmt::Display for SandboxKind {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        let name = match self {
            SandboxKind::Linux => "linux",
            SandboxKind::Generic => "generic",
        };

        fmt.write_str(name)
    }
}

impl SandboxKind {
    #[cfg(feature = "std")]
    fn from_os_str(s: &std::ffi::OsStr) -> Result<Option<SandboxKind>, Error> {
        if s == "auto" {
            Ok(None)
        } else if s == "linux" {
            Ok(Some(SandboxKind::Linux))
        } else if s == "generic" {
            Ok(Some(SandboxKind::Generic))
        } else {
            Err(Error::from_static_str(
                "invalid value of POLKAVM_SANDBOX; supported values are: 'linux', 'generic'",
            ))
        }
    }
}

impl SandboxKind {
    pub fn is_supported(self) -> bool {
        if_compiler_is_supported! {
            {
                match self {
                    SandboxKind::Linux => cfg!(target_os = "linux"),
                    SandboxKind::Generic => cfg!(feature = "generic-sandbox"),
                }
            } else {
                false
            }
        }
    }
}

#[derive(Clone)]
pub struct Config {
    pub(crate) backend: Option<BackendKind>,
    pub(crate) sandbox: Option<SandboxKind>,
    pub(crate) crosscheck: bool,
    pub(crate) allow_experimental: bool,
    pub(crate) allow_dynamic_paging: bool,
    pub(crate) worker_count: usize,
    pub(crate) cache_enabled: bool,
    pub(crate) lru_cache_size: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "std")]
fn env_bool(name: &str) -> Result<Option<bool>, Error> {
    if let Some(value) = std::env::var_os(name) {
        if value == "1" || value == "true" {
            Ok(Some(true))
        } else if value == "0" || value == "false" {
            Ok(Some(false))
        } else {
            bail!("invalid value of {name}; must be either '1' or '0'")
        }
    } else {
        Ok(None)
    }
}

#[cfg(feature = "std")]
fn env_usize(name: &str) -> Result<Option<usize>, Error> {
    if let Some(value) = std::env::var_os(name) {
        if let Ok(value) = value.into_string() {
            if let Ok(value) = value.parse() {
                Ok(Some(value))
            } else {
                bail!("invalid value of {name}; must be a positive integer")
            }
        } else {
            bail!("invalid value of {name}; must be a positive integer")
        }
    } else {
        Ok(None)
    }
}

impl Config {
    /// Creates a new default configuration.
    pub fn new() -> Self {
        Config {
            backend: None,
            sandbox: None,
            crosscheck: false,
            allow_experimental: false,
            allow_dynamic_paging: false,
            worker_count: 2,
            cache_enabled: cfg!(feature = "module-cache"),
            lru_cache_size: 0,
        }
    }

    /// Creates a new default configuration and seeds it from the environment variables.
    pub fn from_env() -> Result<Self, Error> {
        let mut config = Self::new();

        #[cfg(feature = "std")]
        {
            if let Some(value) = std::env::var_os("POLKAVM_BACKEND") {
                config.backend = BackendKind::from_os_str(&value)?;
            }

            if let Some(value) = std::env::var_os("POLKAVM_SANDBOX") {
                config.sandbox = SandboxKind::from_os_str(&value)?;
            }

            if let Some(value) = env_bool("POLKAVM_CROSSCHECK")? {
                config.crosscheck = value;
            }

            if let Some(value) = env_bool("POLKAVM_ALLOW_EXPERIMENTAL")? {
                config.allow_experimental = value;
            }

            if let Some(value) = env_usize("POLKAVM_WORKER_COUNT")? {
                config.worker_count = value;
            }

            if let Some(value) = env_bool("POLKAVM_CACHE_ENABLED")? {
                config.cache_enabled = value;
            }

            if let Some(value) = env_usize("POLKAVM_LRU_CACHE_SIZE")? {
                config.lru_cache_size = if value > u32::MAX as usize { u32::MAX } else { value as u32 };
            }
        }

        Ok(config)
    }

    /// Forces the use of a given backend.
    ///
    /// Default: `None` (automatically pick the best available backend)
    ///
    /// Corresponding environment variable: `POLKAVM_BACKEND` (`auto`, `compiler`, `interpreter`)
    pub fn set_backend(&mut self, backend: Option<BackendKind>) -> &mut Self {
        self.backend = backend;
        self
    }

    /// Gets the currently set backend, if any.
    pub fn backend(&self) -> Option<BackendKind> {
        self.backend
    }

    /// Forces the use of a given sandbox.
    ///
    /// Default: `None` (automatically pick the best available sandbox)
    ///
    /// Corresponding environment variable: `POLKAVM_SANDBOX` (`auto`, `linux`, `generic`)
    pub fn set_sandbox(&mut self, sandbox: Option<SandboxKind>) -> &mut Self {
        self.sandbox = sandbox;
        self
    }

    /// Gets the currently set sandbox, if any.
    pub fn sandbox(&self) -> Option<SandboxKind> {
        self.sandbox
    }

    /// Enables execution cross-checking.
    ///
    /// This will run an interpreter alongside the recompiler and cross-check their execution.
    ///
    /// Should only be used for debugging purposes and *never* enabled by default in production.
    ///
    /// Default: `false`
    ///
    /// Corresponding environment variable: `POLKAVM_CROSSCHECK` (`false`, `true`)
    pub fn set_crosscheck(&mut self, value: bool) -> &mut Self {
        self.crosscheck = value;
        self
    }

    /// Returns whether cross-checking is enabled.
    pub fn crosscheck(&self) -> bool {
        self.crosscheck
    }

    /// Enabling this makes it possible to enable other experimental settings
    /// which are not meant for general use and can introduce unsafety,
    /// break determinism, or just simply be totally broken.
    ///
    /// This should NEVER be used in production unless you know what you're doing.
    ///
    /// Default: `false`
    ///
    /// Corresponding environment variable: `POLKAVM_ALLOW_EXPERIMENTAL` (`true`, `false`)
    pub fn set_allow_experimental(&mut self, value: bool) -> &mut Self {
        self.allow_experimental = value;
        self
    }

    /// Sets the number of worker sandboxes that will be permanently kept alive by the engine.
    ///
    /// This doesn't limit the number of instances that can be instantiated at the same time;
    /// it will just tell the engine how many sandboxes should be cached between instantiations.
    ///
    /// For the Linux sandbox this will decide how many worker processes are kept alive.
    ///
    /// This only has an effect when using a recompiler. For the interpreter this setting will be ignored.
    ///
    /// Default: `2`
    ///
    /// Corresponding environment variable: `POLKAVM_WORKER_COUNT`
    pub fn set_worker_count(&mut self, value: usize) -> &mut Self {
        self.worker_count = value;
        self
    }

    /// Returns the number of worker sandboxes that will be permanently kept alive by the engine.
    pub fn worker_count(&self) -> usize {
        self.worker_count
    }

    /// Returns whether dynamic paging is allowed.
    pub fn allow_dynamic_paging(&self) -> bool {
        self.allow_dynamic_paging
    }

    /// Sets whether dynamic paging is allowed.
    ///
    /// Enabling this increases the minimum system requirements of the recompiler backend:
    ///  - At least Linux 6.7 is required.
    ///  - Unpriviledged `userfaultfd` must be enabled (`/proc/sys/vm/unprivileged_userfaultfd` must be set to `1`).
    ///
    /// Default: `false`
    pub fn set_allow_dynamic_paging(&mut self, value: bool) -> &mut Self {
        self.allow_dynamic_paging = value;
        self
    }

    /// Returns whether module caching is enabled.
    pub fn cache_enabled(&self) -> bool {
        self.cache_enabled
    }

    /// Sets whether module caching is enabled.
    ///
    /// When set to `true` calling [`Module::new`](crate::Module::new) or [`Module::from_blob`](crate::Module::from_blob)
    /// will return an already compiled module if such already exists.
    ///
    /// Requires the `module-cache` compile time feature to be enabled, otherwise has no effect.
    ///
    /// Default: `true` if compiled with `module-cache`, `false` otherwise
    ///
    /// Corresponding environment variable: `POLKAVM_CACHE_ENABLED`
    pub fn set_cache_enabled(&mut self, value: bool) -> &mut Self {
        self.cache_enabled = value;
        self
    }

    /// Returns the LRU cache size.
    pub fn lru_cache_size(&self) -> u32 {
        self.lru_cache_size
    }

    /// Sets the LRU cache size.
    ///
    /// Requires the `module-cache` compile time feature and caching to be enabled, otherwise has no effect.
    ///
    /// When the size of the LRU cache is non-zero then modules that are dropped will be added to the LRU cache,
    /// and will be reused if a compilation of the same program is triggered.
    ///
    /// Default: `0`
    ///
    /// Corresponding environment variable: `POLKAVM_LRU_CACHE_SIZE`
    pub fn set_lru_cache_size(&mut self, value: u32) -> &mut Self {
        self.lru_cache_size = value;
        self
    }
}

/// The type of gas metering.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum GasMeteringKind {
    /// Synchronous gas metering. This will immediately abort the execution if we run out of gas.
    Sync,
    /// Asynchronous gas metering. Has a lower performance overhead compared to synchronous gas metering,
    /// but will only periodically and asynchronously check whether we still have gas remaining while
    /// the program is running.
    ///
    /// With asynchronous gas metering the program can run slightly longer than it would otherwise,
    /// and the exact point *when* it is interrupted is not deterministic, but whether the computation
    /// as a whole finishes under a given gas limit will still be strictly enforced and deterministic.
    ///
    /// This is only a hint, and the VM might still fall back to using synchronous gas metering
    /// if asynchronous metering is not available.
    Async,
}

/// The configuration for a module.
#[derive(Clone)]
pub struct ModuleConfig {
    pub(crate) page_size: u32,
    pub(crate) gas_metering: Option<GasMeteringKind>,
    pub(crate) is_strict: bool,
    pub(crate) step_tracing: bool,
    pub(crate) dynamic_paging: bool,
    pub(crate) aux_data_size: u32,
    pub(crate) allow_sbrk: bool,
    cache_by_hash: bool,
}

impl Default for ModuleConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleConfig {
    /// Creates a new default module configuration.
    pub fn new() -> Self {
        ModuleConfig {
            page_size: 0x1000,
            gas_metering: None,
            is_strict: false,
            step_tracing: false,
            dynamic_paging: false,
            aux_data_size: 0,
            allow_sbrk: true,
            cache_by_hash: false,
        }
    }

    /// Sets the page size used for the module.
    ///
    /// Default: `4096` (4k)
    pub fn set_page_size(&mut self, page_size: u32) -> &mut Self {
        self.page_size = page_size;
        self
    }

    /// Returns the size of the auxiliary data region.
    pub fn aux_data_size(&self) -> u32 {
        self.aux_data_size
    }

    /// Sets the size of the auxiliary data region.
    ///
    /// Default: `0`
    pub fn set_aux_data_size(&mut self, aux_data_size: u32) -> &mut Self {
        self.aux_data_size = aux_data_size;
        self
    }

    /// Sets the type of gas metering to enable for this module.
    ///
    /// Default: `None`
    pub fn set_gas_metering(&mut self, kind: Option<GasMeteringKind>) -> &mut Self {
        self.gas_metering = kind;
        self
    }

    /// Returns whether dynamic paging is enabled.
    pub fn dynamic_paging(&self) -> bool {
        self.dynamic_paging
    }

    /// Sets whether dynamic paging is enabled.
    ///
    /// [`Config::allow_dynamic_paging`] also needs to be `true` for dynamic paging to be enabled.
    ///
    /// Default: `false`
    pub fn set_dynamic_paging(&mut self, value: bool) -> &mut Self {
        self.dynamic_paging = value;
        self
    }

    /// Sets whether step tracing is enabled.
    ///
    /// When enabled [`InterruptKind::Step`](crate::InterruptKind::Step) will be returned by [`RawInstance::run`](crate::RawInstance::run)
    /// for each executed instruction.
    ///
    /// Should only be used for debugging.
    ///
    /// Default: `false`
    pub fn set_step_tracing(&mut self, enabled: bool) -> &mut Self {
        self.step_tracing = enabled;
        self
    }

    /// Sets the strict mode. When disabled it's guaranteed that the semantics
    /// of lazy execution match the semantics of eager execution.
    ///
    /// Should only be used for debugging.
    ///
    /// Default: `false`
    pub fn set_strict(&mut self, is_strict: bool) -> &mut Self {
        self.is_strict = is_strict;
        self
    }

    ///
    /// Sets whether sbrk instruction is allowed.
    ///
    /// When enabled sbrk instruction is not allowed it will lead to a trap, otherwise
    /// sbrk instruction is emulated.
    ///
    /// Default: `true`
    pub fn set_allow_sbrk(&mut self, enabled: bool) -> &mut Self {
        self.allow_sbrk = enabled;
        self
    }

    /// Returns whether the module will be cached by hash.
    pub fn cache_by_hash(&self) -> bool {
        self.cache_by_hash
    }

    /// Sets whether the module will be cached by hash.
    ///
    /// This introduces extra overhead as every time a module compilation is triggered the hash
    /// of the program must be calculated, and in general it is faster to recompile a module
    /// from scratch rather than compile its hash.
    ///
    /// Default: `true`
    pub fn set_cache_by_hash(&mut self, enabled: bool) -> &mut Self {
        self.cache_by_hash = enabled;
        self
    }

    #[cfg(feature = "module-cache")]
    pub(crate) fn hash(&self) -> polkavm_common::hasher::Hash {
        let &ModuleConfig {
            page_size,
            aux_data_size,
            gas_metering,
            is_strict,
            step_tracing,
            dynamic_paging,
            allow_sbrk,
            // Deliberately ignored.
            cache_by_hash: _,
        } = self;

        let mut hasher = polkavm_common::hasher::Hasher::new();
        hasher.update_u32_array([
            page_size,
            aux_data_size,
            match gas_metering {
                None => 0,
                Some(GasMeteringKind::Sync) => 1,
                Some(GasMeteringKind::Async) => 2,
            },
            u32::from(is_strict),
            u32::from(step_tracing),
            u32::from(dynamic_paging),
        ]);
        hasher.finalize()
    }
}
