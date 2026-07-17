// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub use self::fake::*;

mod fake {
    use core::ops::Add;

    #[derive(Clone, Copy)]
    #[allow(non_camel_case_types)]
    pub struct u64x2(pub u64, pub u64);

    impl Add for u64x2 {
        type Output = u64x2;

        fn add(self, rhs: u64x2) -> u64x2 {
            u64x2(self.0.wrapping_add(rhs.0), self.1.wrapping_add(rhs.1))
        }
    }
}
