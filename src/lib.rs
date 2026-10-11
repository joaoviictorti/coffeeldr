//! # coffeeldr
//!
//! A modern and lightweight COFF (Common Object File Format) loader for Windows,
//! designed to execute Beacon Object Files (BOFs) with Rust's safety and performance guarantees.
//!
//! ## Overview
//!
//! `coffeeldr` allows you to load and execute COFF files from disk or memory buffers,
//! supporting x86 and x86_64 architectures. It handles relocations, symbol
//! resolution, and memory protection automatically.
//!
//! ## Getting Started
//!
//! Add `coffeeldr` to your project by updating your `Cargo.toml`:
//!
//! ```bash
//! cargo add coffeeldr
//! ```
//!
//! ## Usage
//!
//! Basic usage loading a COFF from a file and executing it:
//!
//! ```ignore
//! use coffeeldr::CoffLdr;
//!
//! let mut ldr = CoffLdr::new("path/to/bof.o")?;
//! let output = ldr.run("go", None, None)?;
//! println!("{}", output);
//! ```
//!
//! Loading from an in-memory buffer works the same way:
//!
//! ```ignore
//! use coffeeldr::CoffLdr;
//!
//! let coff_data = include_bytes!("bof.o");
//! let mut ldr = CoffLdr::new(coff_data)?;
//! let output = ldr.run("go", None, None)?;
//! ```
//!
//! To use module stomping, specify the target module before running:
//!
//! ```ignore
//! use coffeeldr::CoffLdr;
//!
//! let mut ldr = CoffLdr::new("bof.o")?
//!     .with_module_stomping("xpsservices.dll");
//!
//! let output = ldr.run("go", None, None)?;
//! ```
//!
//! The module should be a DLL that is either already loaded in the process or can be loaded via LoadLibrary. The loader will find its .text section and overwrite it with the COFF code.

#![no_std]
#![doc(
    html_logo_url = "https://www.rust-lang.org/logos/rust-logo-128x128-blk-v2.png",
    html_favicon_url = "https://www.rust-lang.org/favicon.ico",
    html_root_url = "https://docs.rs/coffeeldr/latest"
)]
#![feature(core_intrinsics)]
#![allow(internal_features)]

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
compile_error!("coffeeldr supports only x86 and x86_64 targets");

extern crate alloc;

pub mod beacon;
pub mod error;

mod ffi;
mod loader;
mod parse;

#[doc(inline)]
pub use beacon::BeaconPack;
#[doc(inline)]
pub use loader::CoffLdr;
#[doc(inline)]
pub use error::Result;
