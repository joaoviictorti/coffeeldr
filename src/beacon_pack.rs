use alloc::vec::Vec;
use binrw::io::Write;
use hex::FromHex;

/// Type alias for `Result` with `BeaconPackError` as the error type.
type Result<T> = core::result::Result<T, super::error::BeaconPackError>;

/// A struct that represents a buffer for packing data with size tracking.
pub struct BeaconPack {
    /// The internal buffer where data is stored.
    buffer: Vec<u8>,

    /// Tracks the size of the data currently in the buffer.
    size: u32,
}

impl BeaconPack {
    /// Returns the buffer with the total size packed at the beginning.
    ///
    /// The buffer is prefixed with a 4-byte integer representing the total size of the data.
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - A vector containing the size and the buffer data.
    /// * `Err(Box<dyn Error>)` - An error if writing fails.
    pub fn getbuffer(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(4 + self.buffer.len());
        buf.extend_from_slice(&self.size.to_le_bytes());
        buf.extend_from_slice(&self.buffer);
        
        Ok(buf)
    }

    /// Returns the buffer encoded in hexadecimal format (as bytes).
    ///
    /// # Returns
    ///
    /// * `Ok(Vec<u8>)` - A vector containing the hexadecimal representation of the buffer.
    /// * `Err(Box<dyn Error>)` - An error if encoding or decoding fails.
    pub fn get_buffer_hex(&self) -> Result<Vec<u8>> {
        let buf = self.getbuffer()?;
        Ok(Vec::from_hex(hex::encode(&buf))?)
    }

    /// Adds a 2-byte short value to the buffer.
    ///
    /// # Arguments
    ///
    /// * `short` - The 2-byte integer to be added to the buffer.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the short value is added successfully.
    /// * `Err(Box<dyn Error>)` - An error if writing fails.
    pub fn addshort(&mut self, short: i16) -> Result<()> {
        self.write_i16(short);
        self.size += 2;
        
        Ok(())
    }

    /// Adds a 4-byte integer to the buffer.
    ///
    /// # Arguments
    ///
    /// * `int` - The 4-byte integer to be added to the buffer.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the integer is added successfully.
    /// * `Err(Box<dyn Error>)` - An error if writing fails.
    pub fn addint(&mut self, int: i32) -> Result<()> {
        self.write_i32(int);
        self.size += 4;
        
        Ok(())
    }

    /// Adds a UTF-8 string to the buffer.
    ///
    /// The string is prefixed with its length (as a 4-byte integer) and null-terminated.
    ///
    /// # Arguments
    ///
    /// * `s` - The UTF-8 string to be added to the buffer.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the string is added successfully.
    /// * `Err(Box<dyn Error>)` - An error if writing fails.
    pub fn addstr(&mut self, s: &str) -> Result<()> {
        let s_bytes = s.as_bytes();
        let length = s_bytes.len() as u32 + 1;
        self.write_u32(length);
        self.buffer.write_all(s_bytes)?;

        // Null-termination
        self.write_u8(0);
        self.size += 4 + s_bytes.len() as u32 + 1;

        Ok(())
    }

    /// Adds a UTF-16 wide string to the buffer.
    ///
    /// The wide string is encoded as UTF-16, prefixed with its length (as a 4-byte integer), and null-terminated.
    ///
    /// # Arguments
    ///
    /// * `s` - The wide string (UTF-16) to be added to the buffer.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the wide string is added successfully.
    /// * `Err(io::Error)` - An error if writing fails.
    pub fn addwstr(&mut self, s: &str) -> Result<()> {
        let s_wide: Vec<u16> = s.encode_utf16().collect();
        let length = (s_wide.len() as u32 * 2) + 2;
        self.write_u32(length);
        for wchar in s_wide {
            self.write_u16(wchar);
        }
        
        self.write_u16(0);
        self.size += 4 + length;

        Ok(())
    }

    /// Adds a binary data block to the buffer.
    ///
    /// The data block is prefixed with its length (as a 4-byte integer).
    ///
    /// # Arguments
    ///
    /// * `data` - A slice of bytes representing the binary data.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the binary data is added successfully.
    /// * `Err(io::Error)` - An error if writing fails.
    pub fn addbin(&mut self, data: &[u8]) -> Result<()> {
        let length = data.len() as u32;
        self.write_u32(length);
        self.buffer.write_all(data)?;
        self.size += 4 + length;
        
        Ok(())
    }

    /// Resets the buffer, clearing all data and resetting the size to 0.
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.size = 0;
    }
}

impl BeaconPack {
    /// Writes a single byte to the buffer.
    fn write_u8(&mut self, value: u8) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a 2-byte unsigned integer in little-endian format.
    fn write_u16(&mut self, value: u16) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a 2-byte signed integer in little-endian format.
    fn write_i16(&mut self, value: i16) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a 4-byte unsigned integer in little-endian format.
    fn write_u32(&mut self, value: u32) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    /// Writes a 4-byte signed integer in little-endian format.
    fn write_i32(&mut self, value: i32) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }
}

impl Default for BeaconPack {
    /// Provides a default-initialized `BeaconPack`.
    ///
    /// # Returns
    ///
    /// * A default-initialized `BeaconPack`.
    fn default() -> Self {
        Self {
            buffer: Vec::new(),
            size: 0,
        }
    }
}