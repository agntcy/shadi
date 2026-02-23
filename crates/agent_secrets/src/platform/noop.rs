// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

use crate::{SecretError, SecretResult, SecretStore};
use crate::policy::SecretPolicy;
use crate::memory::SecretBytes;

pub struct NoopSecretStore;

impl NoopSecretStore {
    pub fn new() -> Self {
        Self
    }
}

impl SecretStore for NoopSecretStore {
    fn put(&self, _key: &str, _secret: &[u8], _policy: SecretPolicy) -> SecretResult<()> {
        Err(SecretError::NotSupported)
    }

    fn get(&self, _key: &str) -> SecretResult<SecretBytes> {
        Err(SecretError::NotSupported)
    }

    fn delete(&self, _key: &str) -> SecretResult<()> {
        Err(SecretError::NotSupported)
    }

    fn list_keys(&self) -> SecretResult<Vec<String>> {
        Err(SecretError::NotSupported)
    }
}
