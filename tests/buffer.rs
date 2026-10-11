use coffeeldr::{CoffLdr, Result};

#[test]
fn test_buffer_memory() -> Result<()> {
    let buffer = include_bytes!("../tests/data/whoami.x64.o");
    let mut ldr = CoffLdr::new(buffer)?;
    let output = ldr.run("go", None, None)?;
    
    assert!(
        output.contains("\\") 
            || output.contains("User")
            || output.contains("Account"),
        "whoami buffer-loaded output does not look valid: {output}"
    );

    Ok(())
}

#[test]
fn test_stomping() -> Result<()> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/whoami.x64.o"
    );

    let mut coffee = CoffLdr::new(path)?.with_module_stomping("amsi.dll");
    let output = coffee.run("go", None, None)?;
    
    assert!(
        output.contains("\\")
            || output.contains("User")
            || output.contains("Account"),
        "whoami output (with stomping) looks invalid: {output}"
    );
    
    Ok(())
}
