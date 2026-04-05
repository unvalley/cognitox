//! Storage configuration for the Cognito emulator.

use std::path::PathBuf;

/// Default flush interval for persistent storage (milliseconds).
const FLUSH_INTERVAL_MS: u64 = 500;

/// How the emulator persists its in-memory state.
#[derive(Debug, Clone)]
pub enum StorageMode {
    /// Pure in-memory storage. Data is lost on shutdown.
    Memory,
    /// In-memory storage with periodic file persistence.
    Persistent { data_file: PathBuf },
}

/// Configuration for the storage layer.
#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub mode: StorageMode,
}

impl StorageConfig {
    /// Memory-only storage (no persistence).
    pub fn memory() -> Self {
        Self {
            mode: StorageMode::Memory,
        }
    }

    /// Persistent storage backed by a file.
    pub fn persistent(data_file: PathBuf) -> Self {
        Self {
            mode: StorageMode::Persistent { data_file },
        }
    }

    /// Flush interval used by the persistent backend.
    pub fn flush_interval_ms(&self) -> u64 {
        FLUSH_INTERVAL_MS
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self::memory()
    }
}
