//! [Platform-Agnostic Serialized Keys](https://github.com/paseto-standard/paserk)
//!
//! An extension to [PASETO](https://github.com/paseto-standard/paseto-spec) (AKA Platform-Agnostic Security Tokens),
//! using the [`rusty_paseto`] library as the PASETO implementation underneath.

pub mod id;
// pub mod pbkw;
pub mod wrap;
pub mod pke;
