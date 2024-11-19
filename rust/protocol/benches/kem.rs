//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use libsignal_protocol::kem::{KeyPair, KeyType};
