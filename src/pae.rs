pub fn digest<const N: usize, const M: usize>(
    pieces: [[&[u8]; M]; N],
    out: &mut impl digest::Digest,
) {
    out.update((N as u64).to_le_bytes());
    for piece in pieces {
        write_piece_digest(piece, out);
    }
}

fn write_piece_digest<const M: usize>(piece: [&[u8]; M], out: &mut impl digest::Digest) {
    let len: u64 = piece.iter().map(|x| x.len() as u64).sum();
    out.update(len.to_le_bytes());
    for x in piece {
        out.update(x);
    }
}

pub fn mac<const N: usize, const M: usize>(pieces: [[&[u8]; M]; N], out: &mut impl digest::Mac) {
    out.update(&(N as u64).to_le_bytes());
    for piece in pieces {
        write_piece_mac(piece, out);
    }
}

fn write_piece_mac<const M: usize>(piece: [&[u8]; M], out: &mut impl digest::Mac) {
    let len: u64 = piece.iter().map(|x| x.len() as u64).sum();
    out.update(&len.to_le_bytes());
    for x in piece {
        out.update(x);
    }
}
