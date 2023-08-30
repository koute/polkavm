#[derive(Debug, Default)]
pub struct Trap {
    _private: (),
}

impl core::fmt::Display for Trap {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        // TODO: We should print out the exact reason for the trap.
        fmt.write_str("execution trapped")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Trap {}

#[derive(Debug)]
pub enum ExecutionError<T> {
    Trap(Trap),
    Error(T),
}

impl<T> From<T> for ExecutionError<T> {
    fn from(error: T) -> Self {
        ExecutionError::Error(error)
    }
}

impl<T> core::fmt::Display for ExecutionError<T>
where
    T: core::fmt::Display,
{
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            ExecutionError::Trap(trap) => trap.fmt(fmt),
            ExecutionError::Error(error) => error.fmt(fmt),
        }
    }
}

#[cfg(feature = "std")]
impl<T> std::error::Error for ExecutionError<T> where T: core::fmt::Debug + core::fmt::Display {}
