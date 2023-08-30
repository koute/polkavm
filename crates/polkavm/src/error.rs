use std::borrow::Cow;

macro_rules! bail {
    ($($arg:expr),* $(,)?) => {
        return Err(Error::from_display(format_args!($($arg),*)))
    }
}

pub(crate) use bail;

#[derive(Debug)]
pub struct Error {
    message: Cow<'static, str>,
}

impl From<String> for Error {
    fn from(string: String) -> Self {
        Error { message: string.into() }
    }
}

impl Error {
    pub(crate) fn from_display(message: impl core::fmt::Display) -> Self {
        Error {
            message: Cow::Owned(message.to_string()),
        }
    }

    pub(crate) fn from_static_str(message: &'static str) -> Self {
        Error {
            message: Cow::Borrowed(message),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn context(self, message: impl core::fmt::Display) -> Self {
        let message = match self.message {
            Cow::Borrowed(prefix) => format!("{}: {}", prefix, message),
            Cow::Owned(mut buffer) => {
                use core::fmt::Write;

                write!(&mut buffer, ": {}", message).unwrap();
                buffer
            }
        };

        Error {
            message: Cow::Owned(message),
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        fmt.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

pub type ExecutionError<T = Error> = polkavm_common::error::ExecutionError<T>;
