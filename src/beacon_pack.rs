use alloc::vec::Vec;
use binrw::io::Write;
use hex::FromHex;
use super::error::Result;

/// A struct that represents a buffer for packing data with size tracking.
#[derive(Default)]
pub struct BeaconPack {
    /// The internal buffer where data is stored.
    buffer: Vec<u8>,

    /// Tracks the size of the data currently in the buffer.
    size: u32,
}

impl BeaconPack {
    /// Returns the buffer with the total size packed at the beginning.
    pub fn getbuffer(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(4 + self.buffer.len());
        buf.extend_from_slice(&self.size.to_le_bytes());
        buf.extend_from_slice(&self.buffer);

        Ok(buf)
    }

    /// Returns the buffer encoded in hexadecimal format (as bytes).
    pub fn get_buffer_hex(&self) -> Result<Vec<u8>> {
        let buf = self.getbuffer()?;
        Ok(Vec::from_hex(hex::encode(&buf))?)
    }

    /// Adds a 2-byte short value to the buffer.
    pub fn addshort(&mut self, short: i16) -> Result<()> {
        self.write_i16(short);
        self.size += 2;

        Ok(())
    }

    /// Adds a 4-byte integer to the buffer.
    pub fn addint(&mut self, int: i32) -> Result<()> {
        self.write_i32(int);
        self.size += 4;

        Ok(())
    }

    /// Adds a UTF-8 string to the buffer.
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
    pub fn addbin(&mut self, data: &[u8]) -> Result<()> {
        let length = data.len() as u32;
        self.write_u32(length);
        self.buffer.write_all(data)?;
        self.size += 4 + length;

        Ok(())
    }

    /// Resets the buffer.
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
