pub(crate) mod load;

#[cfg(not(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse4.1"
)))]
mod fe32;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse4.1",
    target_feature = "nyip"
))]
mod fe64;

#[cfg(not(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse4.1"
)))]
pub use fe32::*;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "sse4.1",
    target_feature = "nyip"
))]
pub use fe64::*;

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
