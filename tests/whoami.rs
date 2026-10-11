use coffeeldr::{CoffLdr, Result};

#[test]
fn test_whoami() -> Result<()> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/whoami.x64.o"
    );

    let mut ldr = CoffLdr::new(path)?;
    let output = ldr.run("go", None, None)?;
    
    assert!(
        output.contains("\\")
            || output.contains("User")
            || output.contains("Account")
            || output.contains("Authority"),
        "whoami output does not look valid: {output}"
    );

    Ok(())
}