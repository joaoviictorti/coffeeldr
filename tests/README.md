# CoffeeLdr (Tests)

The tests below cover different usage examples.

## Test structure

There are three main tests:

1. **`test_bof_whoami`**:

    Load and execute the file `whoami.x64.o`, This file executes the `whoami` command on the system.

2. **`test_bof_whoami_with_stomping`**:

    Load and execute the file `whoami.x64.o`, This file executes the `whoami` command on the system (Module Stomping).

3. **`test_bof_ntcreatethread`**:

    Load and execute the file `ntcreatethread.x64.o`. Pass the arguments such as the `PID` and `Shellcode`.

4. **`test_bof_dir`**:

    Load and execute the file `dir.x64.o`. Pass the `C:\` directory as an argument and run the dir command to list the contents.

5. **`test_buffer_memory`**:

    A simple test of a file in memory.

## Dependencies

To run the tests, you will need the following dependencies:

- `hex crate`: For byte manipulation.
- `examples/.o files`: Make sure that the `.o` files mentioned (`whoami.x64.o`, `ntcreatethread.x64.o`, `dir.x64.o`) are present in the `examples/` folder.

## Running the Tests

To run the tests, use the command:
```cmd
cargo test <name-test> -- --nocapture
```
