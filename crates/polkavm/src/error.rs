use polkavm_common::program::ProgramParseError;

macro_rules! bail {
    ($($arg:expr),* $(,)?) => {
        return Err(Error::from_display(format_args!($($arg),*)))
    }
}

pub(crate) use bail;

#[derive(Debug)]
enum ErrorKind {
    Owned(String),
    Static(&'static str),
    ProgramParseError(ProgramParseError),
}

#[derive(Debug)]
#[repr(transparent)]
pub struct Error(ErrorKind);

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
            ErrorKind::Owned(mut buffer) => {
                use core::fmt::Write;
                let _ = write!(&mut buffer, ": {}", message);
                buffer
            }
            error => format!("{}: {}", Error(error), message),
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

impl std::error::Error for Error {}

pub type ExecutionError<T = Error> = polkavm_common::error::ExecutionError<T>;
