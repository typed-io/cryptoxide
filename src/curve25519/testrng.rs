pub(crate) struct GeneratorRaw(u64);

const MUL_FACTOR: u64 = 636_4136_2238_4679_3005;

impl GeneratorRaw {
    pub(crate) const fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        let next = self.0.wrapping_add(102903).wrapping_mul(MUL_FACTOR);
        self.0 = next.wrapping_add(124);
        next
    }

    #[allow(unused)]
    pub fn array_u64<const N: usize>(&mut self) -> [u64; N] {
        let mut out = [0u64; N];
        for o in out.iter_mut() {
            *o = self.next_u64();
        }
        out
    }

    pub fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        for i in 0..N / 8 {
            let ofs = i * 8;
            let bytes = self.next_u64().to_be_bytes();
            out[ofs..ofs + 8].copy_from_slice(&bytes);
        }
        if N % 8 > 0 {
            let ofs = N / 8;
            let rem = N % 8;
            let bytes = self.next_u64().to_be_bytes();
            out[ofs..ofs + rem].copy_from_slice(&bytes[0..rem]);
        }
        out
    }
}

impl Iterator for GeneratorRaw {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.next_u64())
    }
}

pub struct GeneratorOf<T> {
    testdrg: GeneratorRaw,
    remaining: usize,
    f: fn(&mut GeneratorRaw) -> T,
}

pub struct GeneratorOf2<T>(GeneratorOf<T>);
pub struct GeneratorOf3<T>(GeneratorOf<T>);

impl<T> GeneratorOf<T> {
    pub(crate) fn new(seed: u64, cases: usize, f: fn(&mut GeneratorRaw) -> T) -> Self {
        GeneratorOf {
            testdrg: GeneratorRaw::new(seed),
            remaining: cases,
            f,
        }
    }

    pub fn next_value(&mut self) -> T {
        (self.f)(&mut self.testdrg)
    }
}

impl<T> GeneratorOf2<T> {
    pub(crate) fn new(seed: u64, cases: usize, f: fn(&mut GeneratorRaw) -> T) -> Self {
        Self(GeneratorOf::new(seed, cases, f))
    }
}

impl<T> GeneratorOf3<T> {
    #[allow(unused)]
    pub(crate) fn new(seed: u64, cases: usize, f: fn(&mut GeneratorRaw) -> T) -> Self {
        Self(GeneratorOf::new(seed, cases, f))
    }
}

impl<T> Iterator for GeneratorOf<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            None
        } else {
            self.remaining -= 1;
            Some(self.next_value())
        }
    }
}

impl<T> Iterator for GeneratorOf2<T> {
    type Item = (T, T);

    #[allow(unused)]
    fn next(&mut self) -> Option<Self::Item> {
        if self.0.remaining == 0 {
            None
        } else {
            self.0.remaining -= 1;
            Some((self.0.next_value(), self.0.next_value()))
        }
    }
}

impl<T> Iterator for GeneratorOf3<T> {
    type Item = (T, T, T);

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.remaining == 0 {
            None
        } else {
            self.0.remaining -= 1;
            Some((
                self.0.next_value(),
                self.0.next_value(),
                self.0.next_value(),
            ))
        }
    }
}

/*
fn next_fe(gen: &mut GeneratorRaw) -> Fe {
    let mut bytes = gen.bytes();
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    Fe::from_bytes(&bytes)
}
*/
