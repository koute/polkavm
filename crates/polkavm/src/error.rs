use alloc::format;
use alloc::string::{String, ToString};
use polkavm_common::program::ProgramParseError;

macro_rules! bail {
    ($($arg:expr),* $(,)?) => {
        return Err(Error::from_display(format_args!($($arg),*)))
    }
}

macro_rules! bail_static {
    ($arg:expr) => {
        return Err(Error::from_static_str($arg))
    };
}

pub(crate) use bail;
pub(crate) use bail_static;

#[derive(Debug)]
enum ErrorKind {
    Owned(String),
    Static(&'static str),
    ProgramParseError(ProgramParseError),
}

#[derive(Debug)]
#[repr(transparent)]
pub struct Error(ErrorKind);

impl From<&'static str> for Error {
    #[cold]
    fn from(message: &'static str) -> Self {
        Error(ErrorKind::Static(message))
    }
}

impl From<String> for Error {
    #[cold]
    fn from(string: String) -> Self {
        Error(ErrorKind::Owned(string))
    }
}

impl From<ProgramParseError> for Error {
    #[cold]
    fn from(error: ProgramParseError) -> Self {
        Self(ErrorKind::ProgramParseError(error))
    }
}

if_compiler_is_supported! {
    #[cfg(target_os = "linux")]
    impl From<polkavm_linux_raw::Error> for Error {
        #[cold]
        fn from(error: polkavm_linux_raw::Error) -> Self {
            Self(ErrorKind::Owned(error.to_string()))
        }
    }
}

impl Error {
    #[cold]
    pub(crate) fn from_display(message: impl core::fmt::Display) -> Self {
        Error(ErrorKind::Owned(message.to_string()))
    }

    #[cold]
    pub(crate) fn from_static_str(message: &'static str) -> Self {
        Error(ErrorKind::Static(message))
    }

    #[cold]
    pub(crate) fn context(self, message: impl core::fmt::Display) -> Self {
        let string = match self.0 {
            ErrorKind::Owned(buffer) => format!("{}: {}", message, buffer),
            error => format!("{}: {}", message, Error(error)),
        };

        Error(ErrorKind::Owned(string))
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        let message = match &self.0 {
            ErrorKind::Owned(message) => message.as_str(),
            ErrorKind::Static(message) => message,
            ErrorKind::ProgramParseError(error) => return error.fmt(fmt),
        };

        fmt.write_str(message)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}
