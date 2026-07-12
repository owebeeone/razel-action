//! The fail-closed length-framed byte cursor shared by this module's key decoders and the
//! `lib.rs` fingerprint decoder (reached as `crate::artifact::Cur`) — carved out of `artifact.rs`.

use razel_core::Error;

/// A fail-closed byte cursor shared by this module's decoders (and the fingerprint decoder in `lib.rs`).
/// Malformed input is a typed `Error::Invalid` — `checked_add` (no overflow panic), bounds-checked takes.
pub(crate) struct Cur<'a> {
    b: &'a [u8],
    i: usize,
    what: &'static str,
}
impl<'a> Cur<'a> {
    pub(crate) fn new(b: &'a [u8], what: &'static str) -> Self {
        Self { b, i: 0, what }
    }
    pub(crate) fn err(&self, detail: &str) -> Error {
        Error::Invalid { what: self.what.into(), detail: detail.into() }
    }
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.i.checked_add(n).ok_or_else(|| self.err("length overflow"))?;
        if end > self.b.len() {
            return Err(self.err("truncated"));
        }
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }
    pub(crate) fn u64(&mut self) -> Result<u64, Error> {
        let raw = self.take(8)?;
        let arr: [u8; 8] = raw.try_into().map_err(|_| self.err("bad u64"))?;
        Ok(u64::from_be_bytes(arr))
    }
    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        let raw = self.take(4)?;
        let arr: [u8; 4] = raw.try_into().map_err(|_| self.err("bad u32"))?;
        Ok(u32::from_be_bytes(arr))
    }
    pub(crate) fn bytes(&mut self) -> Result<Vec<u8>, Error> {
        let n = self.u64()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    pub(crate) fn str(&mut self) -> Result<String, Error> {
        String::from_utf8(self.bytes()?).map_err(|_| self.err("non-utf8"))
    }
    pub(crate) fn finish(&self) -> Result<(), Error> {
        if self.i != self.b.len() {
            return Err(self.err("trailing bytes"));
        }
        Ok(())
    }
}
