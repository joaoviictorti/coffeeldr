#![allow(unused_imports)]

use coffeeldr::{BeaconPack, CoffeeLdr};
use hex::FromHex;
use std::error::Error;

#[test]
fn test_bof_whoami() -> Result<(), Box<dyn Error>> {
    let mut coffee = CoffeeLdr::new("examples/whoami.x64.o")?;
    let output = coffee.run("go", None, None)?;
    println!("{output}");
    Ok(())
}

#[test]
fn test_bof_whoami_with_stomping() -> Result<(), Box<dyn Error>> {
    let mut coffee = CoffeeLdr::new("examples/whoami.x64.o")?
        .with_module_stomping("amsi.dll");
    let output = coffee.run("go", None, None)?;
    println!("{output}");
    Ok(())
}

#[test]
fn test_bof_ntcreatethread() -> Result<(), Box<dyn Error>> {
    let mut pack = BeaconPack::default();

    // Replace Shellcode
    let buf: [u8; 3] = [0x41, 0x41, 0x41]; 

    pack.addint(23316)?; // PID
    pack.addbin(&buf)?; // Shellcode

    let args = pack.get_buffer_hex()?;
    let mut coffee = CoffeeLdr::new("examples/ntcreatethread.x64.o")?;
    let output = coffee.run("go", Some(args.as_ptr() as _), Some(args.len()))?;
    println!("{output}");

    Ok(())
}

#[test]
fn test_bof_dir() -> Result<(), Box<dyn Error>> {
    let mut pack = BeaconPack::default();

    pack.addstr("C:\\")?;

    let args = pack.get_buffer_hex()?;
    let mut coffee = CoffeeLdr::new("examples/dir.x64.o")?;
    let output = coffee.run("go", Some(args.as_ptr() as _), Some(args.len()))?;
    println!("{output}");

    Ok(())
}

#[test]
fn test_buffer_memory() -> Result<(), Box<dyn Error>> {
    let buffer = include_bytes!("../examples/whoami.x64.o");
    let mut coffee = CoffeeLdr::new(buffer)?;
    let output = coffee.run("go", None, None)?;
    println!("{output}");
    Ok(())
}
