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
                    SandboxKind::Generic => true
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
    pub(crate) trace_execution: bool,
    pub(crate) allow_insecure: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

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

impl Config {
    /// Creates a new default configuration.
    pub fn new() -> Self {
        Config {
            backend: None,
            sandbox: None,
            trace_execution: false,
            allow_insecure: false,
        }
    }

    /// Creates a new default configuration and seeds it from the environment variables.
    pub fn from_env() -> Result<Self, Error> {
        let mut config = Self::new();
        if let Some(value) = std::env::var_os("POLKAVM_BACKEND") {
            config.backend = BackendKind::from_os_str(&value)?;
        }

        if let Some(value) = std::env::var_os("POLKAVM_SANDBOX") {
            config.sandbox = SandboxKind::from_os_str(&value)?;
        }

        if let Some(value) = env_bool("POLKAVM_TRACE_EXECUTION")? {
            config.trace_execution = value;
        }

        if let Some(value) = env_bool("POLKAVM_ALLOW_INSECURE")? {
            config.allow_insecure = value;
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

    /// Enables execution tracing.
    ///
    /// **Requires `set_allow_insecure` to be `true`.**
    ///
    /// Default: `false`
    ///
    /// Corresponding environment variable: `POLKAVM_TRACE_EXECUTION` (`true`, `false`)
    pub fn set_trace_execution(&mut self, value: bool) -> &mut Self {
        self.trace_execution = value;
        self
    }

    /// Returns whether the execution tracing is enabled.
    pub fn trace_execution(&self) -> bool {
        self.trace_execution
    }

    /// Enabling this makes it possible to enable other settings
    /// which can introduce unsafety or break determinism.
    ///
    /// Should only be used for debugging purposes and *never* enabled by default in production.
    ///
    /// Default: `false`
    ///
    /// Corresponding environment variable: `POLKAVM_ALLOW_INSECURE` (`true`, `false`)
    pub fn set_allow_insecure(&mut self, value: bool) -> &mut Self {
        self.allow_insecure = value;
        self
    }
}
