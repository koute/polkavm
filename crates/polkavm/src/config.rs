use crate::error::{bail, Error};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Backend {
    Compiler,
    Interpreter,
}

impl core::fmt::Display for Backend {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        let name = match self {
            Backend::Compiler => "compiler",
            Backend::Interpreter => "interpreter",
        };

        fmt.write_str(name)
    }
}

impl Backend {
    fn from_os_str(s: &std::ffi::OsStr) -> Result<Option<Backend>, Error> {
        if s == "auto" {
            Ok(None)
        } else if s == "interpreter" {
            Ok(Some(Backend::Interpreter))
        } else if s == "compiler" {
            Ok(Some(Backend::Compiler))
        } else {
            Err(Error::from_static_str(
                "invalid value of POLKAVM_BACKEND; supported values are: 'interpreter', 'compiler'",
            ))
        }
    }
}

impl Backend {
    pub fn is_supported(self) -> bool {
        match self {
            Backend::Interpreter => true,
            Backend::Compiler => crate::compiler::IS_SUPPORTED,
        }
    }
}

#[derive(Clone)]
pub struct Config {
    pub(crate) backend: Option<Backend>,
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
            trace_execution: false,
            allow_insecure: false,
        }
    }

    /// Creates a new default configuration and seeds it from the environment variables.
    pub fn from_env() -> Result<Self, Error> {
        let mut config = Self::new();
        if let Some(value) = std::env::var_os("POLKAVM_BACKEND") {
            config.backend = Backend::from_os_str(&value)?;
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
    pub fn set_backend(&mut self, backend: Option<Backend>) -> &mut Self {
        self.backend = backend;
        self
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
