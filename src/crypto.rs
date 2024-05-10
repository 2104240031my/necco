pub mod aes;
pub mod sha3;
pub mod x25519;
pub mod uint;

use std::error::Error;
use std::fmt::Display;


#[derive(Debug)]
pub struct CryptoError {
    err_msg: String
}

impl Error for CryptoError {}

impl Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "crypto error.")
    }
}

impl CryptoError {

    pub fn new(err_msg: String) -> Self {
        return CryptoError{
            err_msg: err_msg
        };
    }

}