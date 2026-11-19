//! Read PE32+ files. Use file offsets on disk and RVAs within the loaded image.
use crate::{Error, Result};
use serde::Serialize;
pub const MAX_IMAGE: usize = 256 * 1024 * 1024;
#[derive(Clone, Debug, Serialize)]
pub struct Section {
    pub name: String,
    pub rva: u32,
    pub size: u32,
    pub executable: bool,
    pub readable: bool,
    pub raw_offset: u32,
    pub raw_size: u32,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Function {
    pub start: u32,
    pub end: u32,
}
#[derive(Clone, Debug)]
pub struct Headers {
    pub base: u64,
    pub size: usize,
    pub headers_size: usize,
    pub sections: Vec<Section>,
    pub exception_rva: u32,
    pub exception_size: u32,
    pub timestamp: u32,
}
fn err(s: &str) -> Error {
    Error::new("PE", s)
}
fn range(b: &[u8], at: usize, len: usize) -> Result<&[u8]> {
    b.get(at..at.checked_add(len).ok_or_else(|| err("offset overflow"))?)
        .ok_or_else(|| err("truncated image"))
}
fn u16at(b: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(range(b, at, 2)?.try_into().unwrap()))
}
fn u32at(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(range(b, at, 4)?.try_into().unwrap()))
}
impl Headers {
    pub fn parse(b: &[u8]) -> Result<Self> {
        if range(b, 0, 2)? != b"MZ" {
            return Err(err("missing DOS signature"));
        }
        let pe = u32at(b, 0x3c)? as usize;
        if range(b, pe, 4)? != b"PE\0\0" || u16at(b, pe + 4)? != 0x8664 {
            return Err(err("expected an x86-64 PE image"));
        }
        let count = u16at(b, pe + 6)? as usize;
        if count == 0 || count > 96 {
            return Err(err("invalid section count"));
        }
        let optional = pe + 24;
        let optional_size = u16at(b, pe + 20)? as usize;
        if optional_size < 144 || u16at(b, optional)? != 0x20b {
            return Err(err("expected PE32+ optional header"));
        }
        range(b, optional, optional_size)?;
        let base = u64::from_le_bytes(range(b, optional + 24, 8)?.try_into().unwrap());
        let size = u32at(b, optional + 56)? as usize;
        let headers_size = u32at(b, optional + 60)? as usize;
        if size == 0 || size > MAX_IMAGE || headers_size > size || headers_size == 0 {
            return Err(err("invalid or oversized image"));
        }
        if u32at(b, optional + 108)? < 4 {
            return Err(err("exception directory is absent"));
        }
        let exception_rva = u32at(b, optional + 136)?;
        let exception_size = u32at(b, optional + 140)?;
        let mut sections = Vec::new();
        for n in 0..count {
            let at = optional + optional_size + n * 40;
            let h = range(b, at, 40)?;
            let name = String::from_utf8_lossy(&h[..8])
                .trim_end_matches('\0')
                .to_string();
            let virtual_size = u32at(b, at + 8)?;
            let rva = u32at(b, at + 12)?;
            let raw_size = u32at(b, at + 16)?;
            let size = virtual_size.max(raw_size);
            let flags = u32at(b, at + 36)?;
            if u64::from(rva) + u64::from(size) > MAX_IMAGE as u64
                || rva as usize + (size as usize) > u32at(b, optional + 56)? as usize
            {
                return Err(err("section extends beyond image"));
            }
            if size > 0 && (rva as usize) < headers_size {
                return Err(err("section overlaps headers"));
            }
            sections.push(Section {
                name,
                rva,
                size,
                executable: flags & 0x20000000 != 0,
                readable: flags & 0x40000000 != 0,
                raw_offset: u32at(b, at + 20)?,
                raw_size,
            });
        }
        sections.sort_by_key(|s| s.rva);
        if sections
            .windows(2)
            .any(|s| u64::from(s[0].rva) + u64::from(s[0].size) > u64::from(s[1].rva))
        {
            return Err(err("overlapping sections"));
        }
        Ok(Self {
            base,
            size,
            headers_size,
            sections,
            exception_rva,
            exception_size,
            timestamp: u32at(b, pe + 8)?,
        })
    }
}
#[derive(Clone, Debug)]
pub struct Image {
    pub headers: Headers,
    pub base: u64,
    pub bytes: Vec<u8>,
    pub functions: Vec<Function>,
}
impl Image {
    pub fn from_file(b: &[u8]) -> Result<Self> {
        let h = Headers::parse(b)?;
        let mut mapped = vec![0; h.size];
        mapped[..h.headers_size].copy_from_slice(range(b, 0, h.headers_size)?);
        for s in &h.sections {
            let src = range(b, s.raw_offset as usize, s.raw_size as usize)?;
            mapped[s.rva as usize..s.rva as usize + src.len()].copy_from_slice(src);
        }
        Self::from_mapped(mapped, h.base)
    }
    pub fn from_mapped(bytes: Vec<u8>, base: u64) -> Result<Self> {
        let headers = Headers::parse(&bytes)?;
        if bytes.len() != headers.size {
            return Err(err("mapped size differs from image header"));
        }
        base.checked_add(bytes.len() as u64)
            .ok_or_else(|| err("loaded address overflow"))?;
        let mut image = Self {
            headers,
            base,
            bytes,
            functions: Vec::new(),
        };
        let ex = image.headers.exception_rva;
        let size = image.headers.exception_size;
        if size == 0 || !size.is_multiple_of(12) || size / 12 > 1_000_000 {
            return Err(err("missing or malformed exception directory"));
        }
        let records = image.read(ex, size as usize)?;
        let mut functions = Vec::new();
        for row in records.as_chunks::<12>().0 {
            let start = u32::from_le_bytes(row[..4].try_into().unwrap());
            let end = u32::from_le_bytes(row[4..8].try_into().unwrap());
            if start == 0 && end == 0 {
                continue;
            }
            if start >= end || !image.executable(start) || !image.executable(end - 1) {
                return Err(err("invalid function range"));
            }
            functions.push(Function { start, end });
        }
        functions.sort_by_key(|f| f.start);
        if functions.windows(2).any(|f| f[0].end > f[1].start) {
            return Err(err("overlapping function ranges"));
        }
        image.functions = functions;
        Ok(image)
    }
    pub fn read(&self, rva: u32, size: usize) -> Result<&[u8]> {
        range(&self.bytes, rva as usize, size)
    }
    pub fn executable(&self, rva: u32) -> bool {
        self.headers.sections.iter().any(|s| {
            s.executable && rva >= s.rva && u64::from(rva) < u64::from(s.rva) + u64::from(s.size)
        })
    }
    pub fn function(&self, rva: u32) -> Option<Function> {
        let n = self.functions.partition_point(|f| f.start <= rva);
        n.checked_sub(1)
            .and_then(|i| self.functions.get(i))
            .copied()
            .filter(|f| rva < f.end)
    }
    pub fn rva(&self, address: u64) -> Result<u32> {
        let r = address
            .checked_sub(self.base)
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| err("address is outside image"))?;
        if r as usize >= self.bytes.len() {
            return Err(err("address is outside image"));
        }
        Ok(r)
    }
    pub fn address(&self, rva: u32) -> Result<u64> {
        self.read(rva, 1)?;
        Ok(self.base + u64::from(rva))
    }
    /// Get the RVA for a named export in this image. Forwarded exports return an error.
    pub fn export_rva(&self, symbol: &str) -> Result<u32> {
        let optional = u32at(&self.bytes, 0x3c)? as usize + 24;
        let export_rva = u32at(&self.bytes, optional + 112)?;
        let export_size = u32at(&self.bytes, optional + 116)?;
        if export_rva == 0 || export_size < 40 {
            return Err(err("missing export directory"));
        }
        let directory = self.read(export_rva, export_size as usize)?;
        let function_count = u32at(directory, 20)? as usize;
        let name_count = u32at(directory, 24)? as usize;
        if function_count > 65_536 || name_count > 65_536 {
            return Err(err("export table exceeds the supported size"));
        }
        let functions = self.read(u32at(directory, 28)?, function_count * 4)?;
        let names = self.read(u32at(directory, 32)?, name_count * 4)?;
        let ordinals = self.read(u32at(directory, 36)?, name_count * 2)?;
        for index in 0..name_count {
            let name_rva = u32at(names, index * 4)? as usize;
            let name = self
                .bytes
                .get(name_rva..)
                .ok_or_else(|| err("invalid export name RVA"))?;
            if !name.starts_with(symbol.as_bytes()) || name.get(symbol.len()) != Some(&0) {
                continue;
            }
            let ordinal = u16at(ordinals, index * 2)? as usize;
            let rva = u32at(functions, ordinal * 4)?;
            if rva >= export_rva && rva - export_rva < export_size {
                return Err(err(&format!(
                    "export {symbol} is forwarded to another module"
                )));
            }
            if !self.executable(rva) {
                return Err(err(&format!(
                    "export {symbol} does not point to executable code"
                )));
            }
            return Ok(rva);
        }
        Err(err(&format!("export {symbol} was not found")))
    }
    pub fn strings(&self, text: &str) -> Vec<u32> {
        let mut result = Vec::new();
        let mut needle = text.as_bytes().to_vec();
        needle.push(0);
        for s in &self.headers.sections {
            if !s.readable || s.executable {
                continue;
            }
            if let Ok(data) = self.read(s.rva, s.size as usize) {
                for off in memchr::memmem::find_iter(data, &needle) {
                    result.push(s.rva + off as u32);
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn file() -> Vec<u8> {
        let mut b = vec![0; 0x600];
        b[..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        b[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
        b[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        let o = 0x98;
        b[o..o + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        b[o + 24..o + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
        b[o + 56..o + 60].copy_from_slice(&0x3000u32.to_le_bytes());
        b[o + 60..o + 64].copy_from_slice(&0x200u32.to_le_bytes());
        b[o + 108..o + 112].copy_from_slice(&16u32.to_le_bytes());
        b[o + 136..o + 140].copy_from_slice(&0x2000u32.to_le_bytes());
        b[o + 140..o + 144].copy_from_slice(&12u32.to_le_bytes());
        for (n, rva, raw, flags) in [
            (0, 0x1000u32, 0x200u32, 0x60000020u32),
            (1, 0x2000, 0x400, 0x40000040),
        ] {
            let a = o + 0xf0 + n * 40;
            b[a + 8..a + 12].copy_from_slice(&0x200u32.to_le_bytes());
            b[a + 12..a + 16].copy_from_slice(&rva.to_le_bytes());
            b[a + 16..a + 20].copy_from_slice(&0x200u32.to_le_bytes());
            b[a + 20..a + 24].copy_from_slice(&raw.to_le_bytes());
            b[a + 36..a + 40].copy_from_slice(&flags.to_le_bytes());
        }
        b[0x200] = 0xc3;
        b[0x400..0x404].copy_from_slice(&0x1000u32.to_le_bytes());
        b[0x404..0x408].copy_from_slice(&0x1001u32.to_le_bytes());
        b
    }
    #[test]
    fn file_and_mapped_views_keep_rvas_distinct() {
        let f = Image::from_file(&file()).unwrap();
        assert_eq!(f.read(0x1000, 1).unwrap(), [0xc3]);
        let m = Image::from_mapped(f.bytes, 0x7ff000000000).unwrap();
        assert_eq!(m.function(0x1000).unwrap().start, 0x1000);
        assert_eq!(m.address(0x1000).unwrap(), 0x7ff000001000);
    }
    #[test]
    fn named_exports_require_a_valid_ordinal_and_executable_target() {
        let mut b = file();
        for (at, value) in [
            (0x98 + 112, 0x2040u32),
            (0x98 + 116, 0x100),
            (0x454, 1),
            (0x458, 1),
            (0x45c, 0x2068),
            (0x460, 0x206c),
            (0x464, 0x2070),
            (0x468, 0x1000),
            (0x46c, 0x2072),
        ] {
            b[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        b[0x472..][..13].copy_from_slice(b"GetCursorPos\0");
        let dll = Image::from_file(&b).unwrap();
        assert_eq!(dll.export_rva("GetCursorPos").unwrap(), 0x1000);
        assert!(dll.export_rva("GetCursor").is_err());
        b[0x468..0x46c].copy_from_slice(&0x2080u32.to_le_bytes());
        let dll = Image::from_file(&b).unwrap();
        assert!(dll
            .export_rva("GetCursorPos")
            .unwrap_err()
            .message
            .contains("forwarded"));
        b[0x470] = 1;
        assert!(Image::from_file(&b)
            .unwrap()
            .export_rva("GetCursorPos")
            .is_err());
    }
    #[test]
    fn malformed_headers_and_ranges_are_rejected() {
        let b = file();
        for n in [0, 2, 63, 0x80, 0x100, 0x200, 0x500] {
            assert!(Image::from_file(&b[..n]).is_err());
        }
        let mut b = file();
        b[0x98 + 56..0x98 + 60].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Image::from_file(&b).is_err());
        let mut b = file();
        b[0x404..0x408].copy_from_slice(&0x4000u32.to_le_bytes());
        assert!(Image::from_file(&b).is_err());
    }
}
