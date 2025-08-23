//! # coffeeldr 🦀
//!
//! A modern and lightweight **COFF (Common Object File Format) loader** for Windows, written in Rust.
//!
//! ## Features
//! - Load COFF files from disk or memory buffers.
//! - Execute COFF entry points directly.
//! - Module stomping support (`.text` section replacement).
//! - Compatible with both `x64` and `x86`.
//! - `#[no_std]` support (with `alloc`).
//!
//! ## Examples
//!
//! ### Loading from File
//! ```no_run
//! use coffeeldr::CoffeeLdr;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let loader = CoffeeLdr::new("path/to/coff_file.o")?;
//!     println!("Loaded COFF from file");
//!     Ok(())
//! }
//! ```
//!
//! ### Loading from Buffer
//! ```no_run
//! use coffeeldr::CoffeeLdr;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let data = include_bytes!("path/to/coff_file.o");
//!     let loader = CoffeeLdr::new(data)?;
//!     println!("Loaded COFF from buffer");
//!     Ok(())
//! }
//! ```
//!
//! ### Executing an Entry Point
//! ```no_run
//! use coffeeldr::CoffeeLdr;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut coffee = CoffeeLdr::new("path/to/coff_file.o")?;
//!     coffee.run("go", None, None)?;
//!     Ok(())
//! }
//! ```
//!
//! ### Using Module Stomping
//! ```no_run
//! use coffeeldr::CoffeeLdr;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let mut coffee = CoffeeLdr::new("path/to/coff_file.o")?
//!         .with_module_stomping("xpsservices.dll");
//!
//!     coffee.run("go", None, None)?;
//!     Ok(())
//! }
//! ```
//!
//! # More Information
//!
//! For additional examples and CLI usage, visit the [repository].
//!
//! [repository]: https://github.com/joaoviictorti/coffeeldr

#![no_std]
#![allow(clippy::ptr_eq)]
#![allow(internal_features, unsafe_op_in_unsafe_fn)]
#![feature(c_variadic, core_intrinsics)]

extern crate alloc;

mod beacon;
mod error;
mod parse;
mod utils;
mod loader;
mod beacon_pack;

pub use loader::*;
pub use beacon_pack::*;
