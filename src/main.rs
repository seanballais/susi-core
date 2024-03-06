mod crypto;
mod error;

use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};

fn main() {
    let password = b"this-is-a-really-long-password";
    let salt = SaltString::generate(&mut OsRng);

    let pass_hash = Argon2::default().hash_password(password, &salt).unwrap();

    let hash = pass_hash.hash.unwrap();
    let hash_bytes = hash.as_bytes();
    println!("{:?}", &hash);
    println!("Length: {}", hash.len());
}
