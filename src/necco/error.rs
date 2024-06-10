use std::error::Error;
use std::fmt::Display;

#[derive(Debug)]
pub struct NeccoError {
    err_msg: String
}

impl Error for NeccoError {}

impl Display for NeccoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Necco error.")
    }
}

impl NeccoError {

    pub fn new(err_msg: String) -> Self {
        return NeccoError{
            err_msg: err_msg
        };
    }

}