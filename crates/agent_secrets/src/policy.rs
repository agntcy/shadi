// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug, Clone, Copy, Default)]
pub struct SecretPolicy {
    pub allow_export: bool,
    pub max_uses: Option<u32>,
    pub ttl_seconds: Option<u64>,
}
