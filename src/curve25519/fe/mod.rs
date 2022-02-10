//! Field Element in ℤ/(2^255-19)
//!
//! The implementation has 2 different limbs representation:
//! * a 32bits architecture 25-26 bits unsaturated limbs using u32 / u64 for multiplication
//! * a 64bits architecture 51 bits unsaturated limbs using u64 / u128 for multiplication
//!
//! The 32 bits architecture is enabled when selecting the "force-32bits"
//! feature and also for known 32 bits architecture (currently just arm32).
//! it's possible that the 32 bits backend get removed alltogether as all main
//! platform (apart from embedded) are 64bits.

#[cfg(any(any(target_arch = "arm"), feature = "force-32bits"))]
pub(crate) mod load;

#[cfg(any(any(target_arch = "arm"), feature = "force-32bits"))]
mod fe32;

#[cfg(not(any(any(target_arch = "arm"), feature = "force-32bits")))]
mod fe64;

#[cfg(any(any(target_arch = "arm"), feature = "force-32bits"))]
pub use fe32::*;

#[cfg(not(any(any(target_arch = "arm"), feature = "force-32bits")))]
pub use fe64::*;

impl Fe {
    pub fn pow25523(&self) -> Fe {
        let z2 = self.square();
        let z8 = z2.square_repeatdly(2);
        let z9 = self * &z8;
        let z11 = &z2 * &z9;
        let z22 = z11.square();
        let z_5_0 = &z9 * &z22;
        let z_10_5 = z_5_0.square_repeatdly(5);
        let z_10_0 = &z_10_5 * &z_5_0;
        let z_20_10 = z_10_0.square_repeatdly(10);
        let z_20_0 = &z_20_10 * &z_10_0;
        let z_40_20 = z_20_0.square_repeatdly(20);
        let z_40_0 = &z_40_20 * &z_20_0;
        let z_50_10 = z_40_0.square_repeatdly(10);
        let z_50_0 = &z_50_10 * &z_10_0;
        let z_100_50 = z_50_0.square_repeatdly(50);
        let z_100_0 = &z_100_50 * &z_50_0;
        let z_200_100 = z_100_0.square_repeatdly(100);
        let z_200_0 = &z_200_100 * &z_100_0;
        let z_250_50 = z_200_0.square_repeatdly(50);
        let z_250_0 = &z_250_50 * &z_50_0;
        let z_252_2 = z_250_0.square_repeatdly(2);
        let z_252_3 = &z_252_2 * self;

        z_252_3
    }

    /// Calculate the invert of the Field element
    ///
    /// the element to invert must be non 0
    pub fn invert(&self) -> Fe {
        let z1 = self;
        let z2 = z1.square();
        let z8 = z2.square_repeatdly(2);
        let z9 = z1 * &z8;
        let z11 = &z2 * &z9;
        let z22 = z11.square();
        let z_5_0 = &z9 * &z22;
        let z_10_5 = z_5_0.square_repeatdly(5);
        let z_10_0 = &z_10_5 * &z_5_0;
        let z_20_10 = z_10_0.square_repeatdly(10);
        let z_20_0 = &z_20_10 * &z_10_0;
        let z_40_20 = z_20_0.square_repeatdly(20);
        let z_40_0 = &z_40_20 * &z_20_0;
        let z_50_10 = z_40_0.square_repeatdly(10);
        let z_50_0 = &z_50_10 * &z_10_0;
        let z_100_50 = z_50_0.square_repeatdly(50);
        let z_100_0 = &z_100_50 * &z_50_0;
        let z_200_100 = z_100_0.square_repeatdly(100);
        let z_200_0 = &z_200_100 * &z_100_0;
        let z_250_50 = z_200_0.square_repeatdly(50);
        let z_250_0 = &z_250_50 * &z_50_0;
        let z_255_5 = z_250_0.square_repeatdly(5);
        let z_255_21 = &z_255_5 * &z11;

        z_255_21
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_serialization() {
        assert_eq!([0; 32], Fe::ZERO.to_bytes());
        assert_eq!(
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            Fe::ONE.to_bytes()
        );
        println!(
            "D2 = {:X?}",
            Fe::from_bytes(&[
                89, 241, 178, 38, 148, 155, 214, 235, 86, 177, 131, 130, 154, 20, 224, 0, 48, 209,
                243, 238, 242, 128, 142, 25, 231, 252, 223, 86, 220, 217, 6, 36
            ])
            .0
        );
        assert_eq!(
            [
                176, 160, 14, 74, 39, 27, 238, 196, 120, 228, 47, 173, 6, 24, 67, 47, 167, 215,
                251, 61, 153, 0, 77, 43, 11, 223, 193, 79, 128, 36, 131, 43
            ],
            Fe::SQRTM1.to_bytes()
        );
        assert_eq!(
            [
                163, 120, 89, 19, 202, 77, 235, 117, 171, 216, 65, 65, 77, 10, 112, 0, 152, 232,
                121, 119, 121, 64, 199, 140, 115, 254, 111, 43, 238, 108, 3, 82
            ],
            Fe::D.to_bytes()
        );
        assert_eq!(
            [
                89, 241, 178, 38, 148, 155, 214, 235, 86, 177, 131, 130, 154, 20, 224, 0, 48, 209,
                243, 238, 242, 128, 142, 25, 231, 252, 223, 86, 220, 217, 6, 36
            ],
            Fe::D2.to_bytes()
        );
    }

    #[test]
    fn add_sub() {
        let x = &Fe::ZERO - &Fe::ONE;
        assert_eq!(Fe::ZERO.to_bytes(), (&x + &Fe::ONE).to_bytes());
        assert_eq!(Fe::ZERO.to_bytes(), (&Fe::ONE - &Fe::ONE).to_bytes());
    }

    #[test]
    fn mul() {
        let mut r0 = [0u8; 32];
        for (i, e) in r0[0..12].iter_mut().enumerate() {
            *e = (4 * i + 12) as u8;
        }

        let random_fes = [r0];

        for r in random_fes {
            let r = Fe::from_bytes(&r);
            assert!(&r * &Fe::ONE == r);
            assert!(&r * &r == r.square());
        }
    }
}
