//! Decoder robustness: arbitrary/garbage input must never panic — only return
//! `Ok` or `Err`. (Deterministic pseudo-random generator, no external deps.)

use ort_proto::{parse_len, Frame};

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn byte(&mut self) -> u8 {
        (self.next() >> 33) as u8
    }
}

#[test]
fn random_inputs_never_panic() {
    let mut rng = Lcg(0x0123_4567_89ab_cdef);
    for _ in 0..50_000 {
        let len = (rng.next() % 64) as usize;
        let buf: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        // Must not panic regardless of result.
        let _ = Frame::decode(&buf);
    }
}

#[test]
fn structured_but_corrupt_frames_never_panic() {
    // Start from valid frame bodies, then corrupt each prefix length.
    let valids = [
        Frame::Close.encode(),
        Frame::ServerAck {
            accepted_suite: 1,
            ek_hash: [0u8; 64],
        }
        .encode(),
        Frame::DataRecord {
            from_server: false,
            ciphertext: vec![1u8; 100],
        }
        .encode(),
    ];
    let mut rng = Lcg(42);
    for base in &valids {
        for _ in 0..2000 {
            let mut b = base.clone();
            if !b.is_empty() {
                let i = (rng.next() as usize) % b.len();
                b[i] = rng.byte();
            }
            let _ = Frame::decode(&b);
        }
    }
}

#[test]
fn length_prefix_never_panics() {
    let mut rng = Lcg(7);
    for _ in 0..10_000 {
        let p = [rng.byte(), rng.byte(), rng.byte(), rng.byte()];
        let _ = parse_len(p);
    }
}
