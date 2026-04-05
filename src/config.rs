//! Storage configuration for the Cognito emulator.

use std::path::PathBuf;

/// How the emulator persists its in-memory state.
#[derive(Debug, Clone)]
pub enum StorageMode {
    /// Pure in-memory storage. Data is lost on shutdown.
    Memory,
    /// In-memory storage with periodic file persistence.
    Persistent {
        data_file: PathBuf,
        flush_interval_ms: u64,
    },
}

/// Configuration for the storage layer.
#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub mode: StorageMode,
}

/// Default flush interval for persistent storage (milliseconds).
pub const DEFAULT_FLUSH_INTERVAL_MS: u64 = 500;

impl StorageConfig {
    /// Memory-only storage (no persistence).
    pub fn memory() -> Self {
        Self {
            mode: StorageMode::Memory,
        }
    }

    /// Persistent storage with the default flush interval.
    pub fn persistent(data_file: PathBuf) -> Self {
        Self {
            mode: StorageMode::Persistent {
                data_file,
                flush_interval_ms: DEFAULT_FLUSH_INTERVAL_MS,
            },
        }
    }

    /// Persistent storage with a custom flush interval.
    pub fn persistent_with_interval(data_file: PathBuf, flush_interval_ms: u64) -> Self {
        Self {
            mode: StorageMode::Persistent {
                data_file,
                flush_interval_ms,
            },
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self::memory()
    }
}
