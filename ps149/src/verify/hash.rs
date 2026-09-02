use sha2::{Digest, Sha256};

pub struct DiskHasher {
    hasher: Sha256,
}

impl DiskHasher {
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    pub fn finalize(self) -> String {
        format!("{:x}", self.hasher.finalize())
    }
}
