//! Pointers into guest memory.
//!
//! Port of unidbg: `unidbg-api/src/main/java/com/github/unidbg/pointer/UnidbgPointer.java`
//! and `UnidbgStructure.java`@7f5da98e.
//!
//! A pointer is a guest address plus the memory it belongs to, so every access
//! is bounds- and mapping-checked by the loader rather than by a raw host
//! address. `share` mirrors unidbg's: it moves the address and keeps the owner.

use std::rc::Rc;

use crate::memory::{Memory, MemoryError};

/// A pointer into guest memory.
#[derive(Clone)]
pub struct Pointer {
    peer: u64,
    size: u64,
    memory: Rc<dyn Memory>,
}

impl std::fmt::Debug for Pointer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Pointer({:#x}, size={:#x})", self.peer, self.size)
    }
}

impl PartialEq for Pointer {
    fn eq(&self, other: &Self) -> bool {
        self.peer == other.peer
    }
}

impl Eq for Pointer {}

impl Pointer {
    /// A pointer at `peer` into `memory`.
    pub fn new(memory: Rc<dyn Memory>, peer: u64) -> Self {
        Pointer {
            peer,
            size: 0,
            memory,
        }
    }

    /// The guest address.
    pub fn peer(&self) -> u64 {
        self.peer
    }

    /// The address truncated to 32 bits, as a 32-bit guest sees it.
    pub fn to_u32(&self) -> u32 {
        self.peer as u32
    }

    /// The address truncated to 32 bits when the guest is 32-bit, as unidbg's
    /// `nativeValue`.
    pub fn native_value(&self) -> u64 {
        if self.memory.pointer_size() == 4 {
            self.peer & 0xffff_ffff
        } else {
            self.peer
        }
    }

    /// The pointer's length, when it names a block.
    pub fn get_size(&self) -> u64 {
        self.size
    }

    /// Sets the pointer's length and returns it (unidbg's `setSize`).
    pub fn set_size(mut self, size: u64) -> Self {
        self.size = size;
        self
    }

    /// The memory this pointer belongs to.
    pub fn memory(&self) -> &Rc<dyn Memory> {
        &self.memory
    }

    /// A pointer `offset` bytes further on, of length `size`.
    pub fn share(&self, offset: u64, size: u64) -> Pointer {
        Pointer {
            peer: self.peer.wrapping_add(offset),
            size,
            memory: Rc::clone(&self.memory),
        }
    }

    // ---- byte access ----------------------------------------------------

    /// Reads `buf.len()` bytes at `offset`.
    pub fn read_bytes(&self, offset: u64, buf: &mut [u8]) -> Result<(), MemoryError> {
        self.memory.read_bytes(self.peer.wrapping_add(offset), buf)
    }

    /// Reads `length` bytes at `offset`.
    pub fn get_bytes(&self, offset: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        let mut buf = vec![0u8; length];
        self.read_bytes(offset, &mut buf)?;
        Ok(buf)
    }

    /// Writes `data` at `offset`.
    pub fn write_bytes(&self, offset: u64, data: &[u8]) -> Result<(), MemoryError> {
        self.memory
            .write_bytes(self.peer.wrapping_add(offset), data)
    }

    /// Reads one byte.
    pub fn read_byte(&self, offset: u64) -> Result<u8, MemoryError> {
        let mut buf = [0u8; 1];
        self.read_bytes(offset, &mut buf)?;
        Ok(buf[0])
    }

    /// Writes one byte.
    pub fn write_byte(&self, offset: u64, value: u8) -> Result<(), MemoryError> {
        self.write_bytes(offset, &[value])
    }

    /// Reads a little-endian `u16`.
    pub fn read_u16(&self, offset: u64) -> Result<u16, MemoryError> {
        let mut buf = [0u8; 2];
        self.read_bytes(offset, &mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    /// Writes a little-endian `u16`.
    pub fn write_u16(&self, offset: u64, value: u16) -> Result<(), MemoryError> {
        self.write_bytes(offset, &value.to_le_bytes())
    }

    /// Reads a little-endian `u32`.
    pub fn read_u32(&self, offset: u64) -> Result<u32, MemoryError> {
        let mut buf = [0u8; 4];
        self.read_bytes(offset, &mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    /// Writes a little-endian `u32`.
    pub fn write_u32(&self, offset: u64, value: u32) -> Result<(), MemoryError> {
        self.write_bytes(offset, &value.to_le_bytes())
    }

    /// Reads a little-endian `u64`.
    pub fn read_u64(&self, offset: u64) -> Result<u64, MemoryError> {
        let mut buf = [0u8; 8];
        self.read_bytes(offset, &mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    /// Writes a little-endian `u64`.
    pub fn write_u64(&self, offset: u64, value: u64) -> Result<(), MemoryError> {
        self.write_bytes(offset, &value.to_le_bytes())
    }

    /// Reads a guest pointer of the guest's width.
    pub fn read_pointer(&self, offset: u64) -> Result<u64, MemoryError> {
        if self.memory.pointer_size() == 4 {
            Ok(u64::from(self.read_u32(offset)?))
        } else {
            self.read_u64(offset)
        }
    }

    /// Writes a guest pointer of the guest's width.
    pub fn write_pointer(&self, offset: u64, value: u64) -> Result<(), MemoryError> {
        if self.memory.pointer_size() == 4 {
            self.write_u32(offset, value as u32)
        } else {
            self.write_u64(offset, value)
        }
    }

    /// Reads a pointer-typed value at `offset`.
    pub fn read_pointer_at(&self, offset: u64) -> Result<Pointer, MemoryError> {
        let peer = self.read_pointer(offset)?;
        Ok(Pointer::new(Rc::clone(&self.memory), peer))
    }

    /// Writes a pointer value at `offset`.
    pub fn write_pointer_at(&self, offset: u64, value: &Pointer) -> Result<(), MemoryError> {
        self.write_pointer(offset, value.peer())
    }

    // ---- arrays ---------------------------------------------------------

    /// Reads `count` bytes.
    pub fn get_byte_array(&self, offset: u64, count: usize) -> Result<Vec<u8>, MemoryError> {
        self.get_bytes(offset, count)
    }

    /// Reads `count` little-endian `u32`s.
    pub fn get_int_array(&self, offset: u64, count: usize) -> Result<Vec<u32>, MemoryError> {
        let bytes = self.get_bytes(offset, count * 4)?;
        Ok(bytes
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("four bytes")))
            .collect())
    }

    /// Reads `count` little-endian `u64`s.
    pub fn get_long_array(&self, offset: u64, count: usize) -> Result<Vec<u64>, MemoryError> {
        let bytes = self.get_bytes(offset, count * 8)?;
        Ok(bytes
            .chunks_exact(8)
            .map(|chunk| u64::from_le_bytes(chunk.try_into().expect("eight bytes")))
            .collect())
    }

    /// Writes little-endian `u32`s.
    pub fn write_int_array(&self, offset: u64, values: &[u32]) -> Result<(), MemoryError> {
        let mut bytes = Vec::with_capacity(values.len() * 4);
        for value in values {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        self.write_bytes(offset, &bytes)
    }

    /// Writes little-endian `u64`s.
    pub fn write_long_array(&self, offset: u64, values: &[u64]) -> Result<(), MemoryError> {
        let mut bytes = Vec::with_capacity(values.len() * 8);
        for value in values {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        self.write_bytes(offset, &bytes)
    }

    // ---- strings --------------------------------------------------------

    /// Reads a NUL-terminated byte string.
    pub fn get_string(&self, offset: u64) -> Result<String, MemoryError> {
        Ok(String::from_utf8_lossy(&self.get_c_string(offset)?).into_owned())
    }

    /// Reads a NUL-terminated byte string's bytes.
    pub fn get_c_string(&self, offset: u64) -> Result<Vec<u8>, MemoryError> {
        let mut out = Vec::new();
        let mut cursor = offset;
        loop {
            let byte = self.read_byte(cursor)?;
            if byte == 0 {
                return Ok(out);
            }
            out.push(byte);
            cursor = cursor.wrapping_add(1);
        }
    }

    /// Writes a NUL-terminated byte string.
    pub fn set_string(&self, offset: u64, value: &str) -> Result<(), MemoryError> {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        self.write_bytes(offset, &bytes)
    }

    /// Reads a NUL-terminated UTF-16 string (a JNI `jchar*`).
    pub fn get_wide_string(&self, offset: u64) -> Result<String, MemoryError> {
        let mut units = Vec::new();
        let mut cursor = offset;
        loop {
            let unit = self.read_u16(cursor)?;
            if unit == 0 {
                return Ok(String::from_utf16_lossy(&units));
            }
            units.push(unit);
            cursor = cursor.wrapping_add(2);
        }
    }

    /// Writes a NUL-terminated UTF-16 string.
    pub fn set_wide_string(&self, offset: u64, value: &str) -> Result<(), MemoryError> {
        let mut bytes = Vec::new();
        for unit in value.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes.extend_from_slice(&0u16.to_le_bytes());
        self.write_bytes(offset, &bytes)
    }

    /// Fills `length` bytes at `offset` with `value`.
    pub fn set_memory(&self, offset: u64, length: u64, value: u8) -> Result<(), MemoryError> {
        let buffer = vec![value; length as usize];
        self.write_bytes(offset, &buffer)
    }
}

impl std::fmt::Display for Pointer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:x}", self.peer)
    }
}
