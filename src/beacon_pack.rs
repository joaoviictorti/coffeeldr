use alloc::vec::Vec;
use binrw::io::Write;
use hex::FromHex;
use crate::error::Result;

/// Buffer used to build Beacon-compatible packed arguments.
///
/// The buffer keeps track of the total payload size and exposes helpers
/// for appending integers, strings, wide strings and raw binary data.
#[derive(Default)]
pub struct BeaconPack {
    /// Internal byte buffer backing this pack.
    buffer: Vec<u8>,

    /// Logical size of the packed payload (excluding the size prefix).
    size: u32,
}

impl BeaconPack {
    /// Returns a copy of the packed buffer with the size prefix prepended.
    ///
    /// The resulting vector starts with a 4-byte little-endian length field,
    /// followed by the raw payload accumulated so far.
    pub fn getbuffer(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(4 + self.buffer.len());
        buf.extend_from_slice(&self.size.to_le_bytes());
        buf.extend_from_slice(&self.buffer);

        Ok(buf)
    }

    /// Returns the packed buffer encoded as hexadecimal bytes.
    ///
    /// The packed payload (including the size prefix) is hex-encoded and
    /// the resulting ASCII representation is returned as a byte vector.
    ///
    /// # Errors
    ///
    /// Propagates any error produced during hex conversion.
    pub fn get_buffer_hex(&self) -> Result<Vec<u8>> {
        let buf = self.getbuffer()?;
        Ok(Vec::from_hex(hex::encode(&buf))?)
    }

    /// Appends a 2-byte signed integer to the buffer.
    ///
    /// The value is written in little-endian format and the tracked size
    /// is increased accordingly.
    pub fn addshort(&mut self, short: i16) {
        self.write_i16(short);
        self.size += 2;
    }

    /// Appends a 4-byte signed integer to the buffer.
    ///
    /// The value is written in little-endian format and the tracked size
    /// is increased accordingly.
    pub fn addint(&mut self, int: i32) {
        self.write_i32(int);
        self.size += 4;
    }

    /// Appends a UTF-8 string with a length prefix and null terminator.
    ///
    /// # Errors
    ///
    /// Propagates any error produced while writing into the internal buffer.
    pub fn addstr(&mut self, s: &str) -> Result<()> {
        let s_bytes = s.as_bytes();
        let length = s_bytes.len() as u32 + 1;
        self.write_u32(length);
        self.buffer.write_all(s_bytes)?;

        // Null terminator.
        self.write_u8(0);
        self.size += 4 + s_bytes.len() as u32 + 1;

        Ok(())
    }

    /// Appends a UTF-16LE wide string with a length prefix and null terminator.
    ///
    /// # Errors
    ///
    /// Propagates any error produced while writing into the internal buffer.
    pub fn addwstr(&mut self, s: &str) {
        let s_wide: Vec<u16> = s.encode_utf16().collect();
        let length = (s_wide.len() as u32 * 2) + 2;
        self.write_u32(length);

        for wchar in s_wide {
            self.write_u16(wchar);
        }

        self.write_u16(0);
        self.size += 4 + length;
    }

    /// Appends a raw binary blob with a length prefix.
    ///
    /// # Errors
    ///
    /// Propagates any error produced while writing into the internal buffer.
    pub fn addbin(&mut self, data: &[u8]) -> Result<()> {
        let length = data.len() as u32;
        self.write_u32(length);
        self.buffer.write_all(data)?;
        self.size += 4 + length;
        Ok(())
    }

    /// Clears the internal buffer and resets the tracked size.
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
