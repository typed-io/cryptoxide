/// Compare two vectors using a fixed number of operations. If the two vectors are not of equal
/// length, the function returns false immediately.
pub fn fixed_time_eq(lhs: &[u8], rhs: &[u8]) -> bool {
    if lhs.len() != rhs.len() {
        false
    } else {
        let mut v = 0;
        for i in 0..lhs.len() {
            let a = lhs[i];
            let b = rhs[i];
            v |= a ^ b;
        }
        v == 0
    }
}

#[cfg(test)]
mod test {
    use crate::util::fixed_time_eq;

    #[test]
    pub fn test_fixed_time_eq() {
        let a = [0, 1, 2];
        let b = [0, 1, 2];
        let c = [0, 1, 9];
        let d = [9, 1, 2];
        let e = [2, 1, 0];
        let f = [2, 2, 2];
        let g = [0, 0, 0];

        assert!(fixed_time_eq(&a, &a));
        assert!(fixed_time_eq(&a, &b));

        assert!(!fixed_time_eq(&a, &c));
        assert!(!fixed_time_eq(&a, &d));
        assert!(!fixed_time_eq(&a, &e));
        assert!(!fixed_time_eq(&a, &f));
        assert!(!fixed_time_eq(&a, &g));
    }
}
