//! The canonical `CanonicalEffect` (`ops` blob) wire codec — the SINGLE implementation shared by the
//! server follower (`crates/rpc::contracts`) and the browser follower. A `submitEffect(caseId, bytes
//! ops)` carries the effect as the runtime's own canonical encoding ([`CanonicalEffect::encode`]); we
//! decode it and recompute the `effect_hash` from the decoded ops (never trusting a hash on the wire —
//! I1), so two interpreters submitting the same ops always group in the quorum tally.
//!
//! Layout: `count(u32 BE) ‖ [op]`, each op a 1-byte tag + fixed-width BE fields (Transfer=0, Refund=1,
//! OpenStream=2, StopStream=3, SetVar=4, Abort=5; Address=20B, u128=16B BE, u64=8B BE, hash=32B). The
//! tags must match `ubi2_runtime::Op::tag()`.

use ubi2_runtime::{CanonicalEffect, Hash, Op};

const TAG_TRANSFER: u8 = 0;
const TAG_REFUND: u8 = 1;
const TAG_OPEN_STREAM: u8 = 2;
const TAG_STOP_STREAM: u8 = 3;
const TAG_SET_VAR: u8 = 4;
const TAG_ABORT: u8 = 5;

/// Encode a [`CanonicalEffect`] into the wire `ops` blob (the runtime's canonical encoding).
pub fn encode_effect(effect: &CanonicalEffect) -> Vec<u8> {
    effect.encode()
}

/// Decode a wire `ops` blob into a [`CanonicalEffect`], recomputing the `effect_hash` from the decoded
/// ops. Fail-closed: a malformed blob is rejected with a precise reason so the tx reverts rather than
/// committing a half-parsed effect.
pub fn decode_effect(blob: &[u8]) -> Result<CanonicalEffect, String> {
    let mut c = Cursor::new(blob);
    let count = c.u32()? as usize;
    if count > blob.len() {
        return Err("op count exceeds blob length".into());
    }
    let mut ops = Vec::with_capacity(count);
    for _ in 0..count {
        let tag = c.u8()?;
        let op = match tag {
            TAG_TRANSFER => Op::Transfer {
                to: c.addr()?,
                amount: c.u128()?,
            },
            TAG_REFUND => Op::Refund {
                party: c.addr()?,
                amount: c.u128()?,
            },
            TAG_OPEN_STREAM => Op::OpenStream {
                to: c.addr()?,
                rate: c.u128()?,
                deposit: c.u128()?,
            },
            TAG_STOP_STREAM => Op::StopStream { id: c.u64()? },
            TAG_SET_VAR => Op::SetVar {
                key: c.hash()?,
                value: c.hash()?,
            },
            TAG_ABORT => Op::Abort {
                reason_hash: c.hash()?,
            },
            _ => return Err("unknown op tag".into()),
        };
        ops.push(op);
    }
    if !c.is_empty() {
        return Err("trailing bytes after ops".into());
    }
    Ok(CanonicalEffect::new(ops))
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.pos + n > self.buf.len() {
            return Err("unexpected end of ops blob".into());
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, String> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Result<u64, String> {
        let s = self.take(8)?;
        let mut b = [0u8; 8];
        b.copy_from_slice(s);
        Ok(u64::from_be_bytes(b))
    }
    fn u128(&mut self) -> Result<u128, String> {
        let s = self.take(16)?;
        let mut b = [0u8; 16];
        b.copy_from_slice(s);
        Ok(u128::from_be_bytes(b))
    }
    fn addr(&mut self) -> Result<[u8; 20], String> {
        let s = self.take(20)?;
        let mut b = [0u8; 20];
        b.copy_from_slice(s);
        Ok(b)
    }
    fn hash(&mut self) -> Result<Hash, String> {
        let s = self.take(32)?;
        let mut b = [0u8; 32];
        b.copy_from_slice(s);
        Ok(b)
    }
}
