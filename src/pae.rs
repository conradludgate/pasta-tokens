pub trait WriteBytes {
    fn update(&mut self, slice: &[u8]);
}

pub struct Mac<'a, M: digest::Mac>(pub &'a mut M);

impl<'a, M: digest::Mac> WriteBytes for Mac<'a, M> {
    fn update(&mut self, slice: &[u8]) {
        self.0.update(slice)
    }
}

pub struct Digest<'a, M: digest::Digest>(pub &'a mut M);

impl<'a, M: digest::Digest> WriteBytes for Digest<'a, M> {
    fn update(&mut self, slice: &[u8]) {
        self.0.update(slice)
    }
}

impl WriteBytes for Vec<u8> {
    fn update(&mut self, slice: &[u8]) {
        self.extend_from_slice(slice)
    }
}

#[allow(dead_code)]
pub fn pae<const N: usize>(pieces: [&[&[u8]]; N], out: &mut impl WriteBytes) {
    out.update(&(N as u64).to_le_bytes());
    for piece in pieces {
        write_piece(piece, out);
    }
}

fn write_piece(piece: &[&[u8]], out: &mut impl WriteBytes) {
    let len: u64 = piece.iter().map(|x| x.len() as u64).sum();
    out.update(&len.to_le_bytes());
    for x in piece {
        out.update(x);
    }
}

#[test]
fn test() {
    let mut v = Vec::new();

    pae([], &mut v);
    assert_eq!(v, b"\x00\x00\x00\x00\x00\x00\x00\x00");
    v.clear();

    pae([&[b""]], &mut v);
    assert_eq!(
        v,
        b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    );
    v.clear();

    pae([&[b"test"]], &mut v);
    assert_eq!(
        v,
        b"\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00test"
    );
    v.clear();
}
