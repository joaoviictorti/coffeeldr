use alloc::vec::Vec;

use binrw::io::Write;
use hex::FromHex;

use crate::error::Result;

/// Builds a Beacon-compatible argument buffer.
///
/// The buffer tracks the total payload size and provides helpers for
/// appending integers, strings, wide strings and raw binary data. Use
/// [`getbuffer`](Self::getbuffer) to retrieve the final packed payload.
///
/// # Examples
///
/// ```
/// use coffeeldr::BeaconPack;
///
/// let mut pack = BeaconPack::default();
/// pack.addint(42);
/// pack.addstr("hello")?;
///
/// let buf = pack.getbuffer()?;
/// # Ok::<(), coffeeldr::error::Error>(())
/// ```
#[derive(Default, Debug)]
pub struct BeaconPack {
    buffer: Vec<u8>,
    size: u32,
}

impl BeaconPack {
    /// Returns a copy of the packed buffer with a 4-byte size prefix.
    ///
    /// # Examples
    ///
    /// ```
    /// use coffeeldr::BeaconPack;
    ///
    /// let mut pack = BeaconPack::default();
    /// pack.addint(100);
    ///
    /// let buf = pack.getbuffer()?;
    /// assert_eq!(buf.len(), 8); // 4-byte size + 4-byte int
    /// # Ok::<(), coffeeldr::error::Error>(())
    /// ```
    pub fn getbuffer(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(4 + self.buffer.len());
        buf.extend_from_slice(&self.size.to_le_bytes());
        buf.extend_from_slice(&self.buffer);

        Ok(buf)
    }

    /// Returns the packed buffer encoded as hexadecimal bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use coffeeldr::BeaconPack;
    ///
    /// let mut pack = BeaconPack::default();
    /// pack.addint(0x41);
    ///
    /// let hex_buf = pack.get_buffer_hex()?;
    /// # Ok::<(), coffeeldr::error::Error>(())
    /// ```
    pub fn get_buffer_hex(&self) -> Result<Vec<u8>> {
        let buf = self.getbuffer()?;
        Ok(Vec::from_hex(hex::encode(&buf))?)
    }

    /// Appends a 2-byte signed integer in little-endian format.
    ///
    /// # Examples
    ///
    /// ```
    /// use coffeeldr::BeaconPack;
    ///
    /// let mut pack = BeaconPack::default();
    /// pack.addshort(1024);
    /// ```
    pub fn addshort(&mut self, short: i16) {
        self.write_i16(short);
        self.size += 2;
    }

    /// Appends a 4-byte signed integer in little-endian format.
    ///
    /// # Examples
    ///
    /// ```
    /// use coffeeldr::BeaconPack;
    ///
    /// let mut pack = BeaconPack::default();
    /// pack.addint(42);
    /// ```
    pub fn addint(&mut self, int: i32) {
        self.write_i32(int);
        self.size += 4;
    }

    /// Appends a NUL-terminated UTF-8 string with a length prefix.
    ///
    /// # Examples
    ///
    /// ```
    /// use coffeeldr::BeaconPack;
    ///
    /// let mut pack = BeaconPack::default();
    /// pack.addstr("C:\\Windows")?;
    /// # Ok::<(), coffeeldr::error::Error>(())
    /// ```
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

    /// Appends a NUL-terminated UTF-16LE wide string with a length prefix.
    ///
    /// # Examples
    ///
    /// ```
    /// use coffeeldr::BeaconPack;
    ///
    /// let mut pack = BeaconPack::default();
    /// pack.addwstr("C:\\Windows");
    /// ```
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
    /// # Examples
    ///
    /// ```
    /// use coffeeldr::BeaconPack;
    ///
    /// let mut pack = BeaconPack::default();
    /// pack.addbin(&[0xDE, 0xAD, 0xBE, 0xEF])?;
    /// # Ok::<(), coffeeldr::error::Error>(())
    /// ```
    pub fn addbin(&mut self, data: &[u8]) -> Result<()> {
        let length = data.len() as u32;
        self.write_u32(length);
        self.buffer.write_all(data)?;
        self.size += 4 + length;
        Ok(())
    }

    /// Clears the buffer and resets the size counter.
    ///
    /// # Examples
    ///
    /// ```
    /// use coffeeldr::BeaconPack;
    ///
    /// let mut pack = BeaconPack::default();
    /// pack.addint(42);
    /// pack.reset();
    ///
    /// let buf = pack.getbuffer()?;
    /// assert_eq!(buf.len(), 4); // only the size prefix remains
    /// # Ok::<(), coffeeldr::error::Error>(())
    /// ```
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.size = 0;
    }

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
