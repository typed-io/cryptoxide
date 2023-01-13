#![allow(unreachable_code)]
#![allow(dead_code)]

pub fn avx_available() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        #[cfg(feature = "std")] {
            return std::is_x86_feature_detected!("avx");
        }
        #[cfg(all(not(feature = "std"), target_feature = "avx"))] {
            return true;
        }
    }
    return false;
}

pub fn avx2_available() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        #[cfg(feature = "std")] {
            return std::is_x86_feature_detected!("avx2");
        }
        #[cfg(all(not(feature = "std"), target_feature = "avx2"))] {
            return true;
        }
    }
    return false;
}

pub fn sse4_1_available() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        #[cfg(feature = "std")] {
            return std::is_x86_feature_detected!("sse4.1");
        }
        #[cfg(all(not(feature = "std"), target_feature = "sse4.1"))] {
            return true;
        }
    }
    return false;
}