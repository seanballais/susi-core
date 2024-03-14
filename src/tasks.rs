pub trait Task {
    fn run(&self);
}

pub struct EncryptionTask {}

pub struct DecryptionTask {}
