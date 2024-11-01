# coffeeldr 🦀 

![Rust](https://img.shields.io/badge/made%20with-Rust-red)
![Platform](https://img.shields.io/badge/platform-windows-blueviolet)
![Forks](https://img.shields.io/github/forks/joaoviictorti/coffeeldr)
![Stars](https://img.shields.io/github/stars/joaoviictorti/coffeeldr)
![License](https://img.shields.io/github/license/joaoviictorti/coffeeldr)

`coffeeldr` is a modern and lightweight COFF (Common Object File Format) loader for Windows written in Rust, designed to run COFF files on Windows. It supports both 32-bit and 64-bit architectures and allows you to load and execute COFF files from files or memory buffers with Rust’s safety and performance guarantees.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Loading from File](#loading-from-file)
  - [Loading from Buffer](#loading-from-buffer)
  - [Executing a COFF File](#executing-a-coff-file)
- [CLI](#cli)
  - [Input Processing in CLI](#input-processing-in-cli)
- [Contributing to coffeeldr](#contributing-to-coffeeldr)
- [References](#references)
- [License](#license)

## Features

- ✅ Load COFF files from disk or in-memory buffers.
- ✅ 32-bit and 64-bit support.
- ✅ Memory management: Automatically adjusts memory protections to ensure execution (read, write, execute permissions).
- ✅ Dynamic relocation handling.
- ✅ Fully written in Rust with safety and performance in mind.
- ✅ Easy CLI integration with flexible input handling.

## Installation

Add `coffeeldr` to your project by updating your `Cargo.toml`:

```powershell
cargo add coffeeldr
```

## Usage

### Loading from File

To load a COFF file from the filesystem:
```rust
use coffeeldr::CoffeeLdr;

let loader = CoffeeLdr::new("path/to/coff_file.o");
match loader {
    Ok(ldr) => {
        println!("COFF successfully loaded from file!");
        // Execute the entry point or manipulate the COFF as needed
    },
    Err(e) => println!("Error loading COFF: {:?}", e),
}
```

### Loading from Buffer

To load a COFF from an in-memory buffer:
```rust
use coffeeldr::CoffeeLdr;

let coff_data = include_bytes!("path/to/coff_file.o");
let loader = CoffeeLdr::new(coff_data);
match loader {
    Ok(ldr) => {
        println!("COFF successfully loaded from buffer!");
        // Execute the entry point or manipulate the COFF as needed
    },
    Err(e) => println!("Error loading COFF: {:?}", e),
}
```

### Executing a COFF File

Once the COFF file is loaded, you can execute it by specifying the entry point:
```rust
let coffee = CoffeeLdr::new("path/to/coff_file.o").unwrap();
coffee.run("entry_point_function_name", None, None).unwrap();
```

This method will search for the specified entry point and execute it.

## CLI

`coffeeldr` also provides a convenient CLI tool for interacting with COFF files directly from the command line.

Example Command:
```cmd
coffee.exe --bof path/to/coff_file.o --entrypoint go
```

### Input Processing in CLI

These are the types of parameters that the tool accepts for processing:

- `/short:<value>`: Adds a short (`i16`) value.
- `/int:<value>`: Adds an integer (`i32`) value.
- `/str:<value>`: Adds a string.
- `/wstr:<value>`: Adds a wide string.
- `/bin:<base64-data>`: Adds binary data decoded from `base64`.

Example command using [`ntcreatethread.o`](https://github.com/trustedsec/CS-Remote-OPs-BOF/blob/main/Injection/ntcreatethread/ntcreatethread.x64.o):
```cmd
coffee.exe --bof ntcreatethread.o --entrypoint go /int:4732 /bin:Y29mZmVlbGRy..
```

Another example using [`dir.o`](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/master/SA/dir/dir.x64.o):
```cmd
coffee.exe --bof dir.o --entrypoint go /str:C:\
```

## Contributing to coffeeldr
To contribute to **coffeeldr**, follow these steps:

1. Fork this repository.
2. Create a branch: `git checkout -b <branch_name>`.
3. Make your changes and commit them: `git commit -m '<commit_message>'`.
4. Push your changes to your branch: `git push origin <branch_name>`.
5. Create a pull request.

Alternatively, consult the [GitHub documentation](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests) on how to create a pull request.

## References

- <https://github.com/HavocFramework/Havoc>
- <https://otterhacker.github.io/Malware/CoffLoader.html>
- <https://github.com/trustedsec/COFFLoader>

## License

This project is licensed under the MIT License. See the [LICENSE](/LICENSE) file for details.