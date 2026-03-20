// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use zeroize::Zeroize;

pub struct SecretBytes {
    bytes: Vec<u8>,
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretBytes")
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn expose<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(&self.bytes)
    }

    pub fn into_vec(mut self) -> Vec<u8> {
        let mut out = Vec::new();
        std::mem::swap(&mut out, &mut self.bytes);
        out
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expose_returns_expected_bytes() {
        let secret = SecretBytes::new(b"value".to_vec());
        let got = secret.expose(|bytes| bytes.to_vec());
        assert_eq!(got, b"value");
    }

    #[test]
    fn into_vec_returns_owned_bytes() {
        let secret = SecretBytes::new(b"value".to_vec());
        let out = secret.into_vec();
        assert_eq!(out, b"value");
    }
}
