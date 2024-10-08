use std::io::{self, Write};
use byteorder::{LittleEndian, WriteBytesExt};

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
    /// - `Result<Vec<u8>, io::Error>`: A vector containing the size and the buffer data, or an error if writing fails.
    pub fn getbuffer(&self) -> Result<Vec<u8>, io::Error> {
        let mut buf = Vec::new();
        buf.write_u32::<LittleEndian>(self.size)?;
        buf.extend_from_slice(&self.buffer);
        
        Ok(buf)
    }

    /// Adds a 2-byte short value to the buffer.
    ///
    /// # Arguments
    ///
    /// - `short`: The 2-byte integer to be added to the buffer.
    ///
    /// # Returns
    ///
    /// - `Result<(), io::Error>`: Ok if the short value is added successfully, or an error if writing fails.
    pub fn addshort(&mut self, short: i16) -> Result<(), io::Error> {
        self.buffer.write_i16::<LittleEndian>(short)?;
        self.size += 2;
        
        Ok(())
    }
    /// Adds a 4-byte integer to the buffer.
    ///
    /// # Arguments
    ///
    /// - `int`: The 4-byte integer to be added to the buffer.
    ///
    /// # Returns
    ///
    /// - `Result<(), io::Error>`: Ok if the integer is added successfully, or an error if writing fails.
    pub fn addint(&mut self, int: i32) -> Result<(), io::Error> {
        self.buffer.write_i32::<LittleEndian>(int)?;
        self.size += 4;
        
        Ok(())
    }

    /// Adds a UTF-8 string to the buffer.
    ///
    /// The string is prefixed with its length (as a 4-byte integer) and null-terminated.
    ///
    /// # Arguments
    ///
    /// - `s`: The UTF-8 string to be added to the buffer.
    ///
    /// # Returns
    ///
    /// - `Result<(), io::Error>`: Ok if the string is added successfully, or an error if writing fails.
    pub fn addstr(&mut self, s: &str) -> Result<(), io::Error> {
        let s_bytes = s.as_bytes();
        let length = s_bytes.len() as u32 + 1;
        self.buffer.write_u32::<LittleEndian>(length)?;
        self.buffer.write_all(s_bytes)?;
        self.buffer.write_u8(0)?;
        self.size += 4 + s_bytes.len() as u32 + 1;

        Ok(())
    }

    /// Adds a UTF-16 wide string to the buffer.
    ///
    /// The wide string is encoded as UTF-16, prefixed with its length (as a 4-byte integer), and null-terminated.
    ///
    /// # Arguments
    ///
    /// - `s`: The wide string (UTF-16) to be added to the buffer.
    ///
    /// # Returns
    ///
    /// - `Result<(), io::Error>`: Ok if the wide string is added successfully, or an error if writing fails.
    pub fn addwstr(&mut self, s: &str) -> Result<(), io::Error> {
        let s_wide: Vec<u16> = s.encode_utf16().collect();
        let length = (s_wide.len() as u32 * 2) + 2;
        self.buffer.write_u32::<LittleEndian>(length)?;
        for wchar in s_wide {
            self.buffer.write_u16::<LittleEndian>(wchar)?;
        }
        self.buffer.write_u16::<LittleEndian>(0)?;
        self.size += 4 + length;

        Ok(())
    }

    /// Adds a binary data block to the buffer.
    ///
    /// The data block is prefixed with its length (as a 4-byte integer).
    ///
    /// # Arguments
    ///
    /// - `data`: A slice of bytes representing the binary data.
    ///
    /// # Returns
    ///
    /// - `Result<(), io::Error>`: Ok if the binary data is added successfully, or an error if writing fails.
    pub fn addbin(&mut self, data: &[u8]) -> Result<(), io::Error> {
        let length = data.len() as u32;
        self.buffer.write_u32::<LittleEndian>(length)?;
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

impl Default for BeaconPack {
    /// Provides a default-initialized `BeaconPack`.
    ///
    /// # Returns
    ///
    /// - `Self`: A default-initialized `BeaconPack`.
    fn default() -> Self {
        Self {
            buffer: Vec::new(),
            size: 0,
        }
    }
}