#[derive(Clone)]
pub(super) struct Test<const OUTPUT: usize> {
    pub input: &'static [u8],
    pub output: [u8; OUTPUT],
}

#[derive(Clone)]
pub(super) struct TestKey<const OUTPUT: usize> {
    pub input: &'static [u8],
    pub key: &'static [u8],
    pub output: [u8; OUTPUT],
}

// a simple hashing test framework based on passing closures
pub(super) fn test_hashing<
    A,
    T,
    New,
    Update,
    UpdateMut,
    Final,
    Reset,
    FinalReset,
    const OUTPUT: usize,
>(
    ivs: &[Test<OUTPUT>],
    alg: A,
    new: New,
    update: Update,
    update_mut: UpdateMut,
    finalize: Final,
    finalize_reset: FinalReset,
    reset: Reset,
) where
    A: core::fmt::Debug + Clone + Copy + PartialEq + Eq + core::hash::Hash,
    T: Clone,
    New: Fn(A) -> T,
    Update: Fn(T, &[u8]) -> T,
    UpdateMut: Fn(&mut T, &[u8]),
    Final: Fn(T) -> [u8; OUTPUT],
    FinalReset: Fn(&mut T) -> [u8; OUTPUT],
    Reset: Fn(&mut T),
{
    for (i, iv) in ivs.iter().enumerate() {
        // Test that it works when accepting the message all at once
        {
            let context = new(alg);
            let context = update(context, iv.input);
            let output = finalize(context);
            assert_eq!(iv.output, output, "IV test one-shot {} failed", i);
        }

        // Test that update_mut works in place correctly
        {
            let mut context = new(alg);
            update_mut(&mut context, iv.input);
            let output = finalize(context);
            assert_eq!(iv.output, output, "IV test one-shot {} failed", i);
        }

        // Test that it works when accepting the message byte-by-byte
        {
            let mut context = new(alg);
            for input_byte in iv.input.chunks(1) {
                context = update(context, input_byte);
            }
            let output = finalize(context);
            assert_eq!(iv.output, output, "IV test incremental(1) {} failed", i);
        }

        // Test that it works when accepting the message 5 bytes per 5 bytes
        {
            let mut context = new(alg);
            for input_byte in iv.input.chunks(5) {
                context = update(context, input_byte);
            }
            let output = finalize(context);
            assert_eq!(iv.output, output, "IV test incremental(5) {} failed", i);
        }

        // Test that reset works as expected
        {
            let mut context = new(alg);
            context = update(context, b"some arbitrary data");
            reset(&mut context);
            context = update(context, iv.input);
            let output = finalize(context);
            assert_eq!(iv.output, output, "IV test reset {} failed", i);
        }

        {
            let mut context = new(alg);
            context = update(context, b"some arbitrary data");
            reset(&mut context);
            context = update(context, iv.input);
            let output = finalize_reset(&mut context);
            assert_eq!(iv.output, output, "IV test finalize-reset {} failed", i);
            assert!(
                finalize(new(alg)) == finalize(context),
                "context after finalize-reset not correct"
            );
        }
    }
}

// a simple hashing test framework based on passing closures
pub(super) fn test_hashing_keyed<
    A,
    T,
    New,
    Update,
    UpdateMut,
    Final,
    Reset,
    FinalReset,
    const OUTPUT: usize,
>(
    ivs: &[TestKey<OUTPUT>],
    alg: A,
    new: New,
    update: Update,
    update_mut: UpdateMut,
    finalize: Final,
    finalize_reset: FinalReset,
    reset: Reset,
) where
    A: core::fmt::Debug + Clone + Copy + PartialEq + Eq + core::hash::Hash,
    T: Clone,
    New: Fn(A, &[u8]) -> T,
    Update: Fn(T, &[u8]) -> T,
    UpdateMut: Fn(&mut T, &[u8]),
    Final: Fn(T) -> [u8; OUTPUT],
    FinalReset: Fn(&mut T, &[u8]) -> [u8; OUTPUT],
    Reset: Fn(&mut T, &[u8]),
{
    for (i, iv) in ivs.iter().enumerate() {
        // Test that it works when accepting the message all at once
        {
            let context = new(alg, iv.key);
            let context = update(context, iv.input);
            let output = finalize(context);
            assert_eq!(iv.output, output, "IV test one-shot {} failed", i);
        }

        // Test that update_mut works in place correctly
        {
            let mut context = new(alg, iv.key);
            update_mut(&mut context, iv.input);
            let output = finalize(context);
            assert_eq!(iv.output, output, "IV test one-shot {} failed", i);
        }

        // Test that it works when accepting the message byte-by-byte
        {
            let mut context = new(alg, iv.key);
            for input_byte in iv.input.chunks(1) {
                context = update(context, input_byte);
            }
            let output = finalize(context);
            assert_eq!(iv.output, output, "IV test incremental(1) {} failed", i);
        }

        // Test that it works when accepting the message 5 bytes per 5 bytes
        {
            let mut context = new(alg, iv.key);
            for input_byte in iv.input.chunks(5) {
                context = update(context, input_byte);
            }
            let output = finalize(context);
            assert_eq!(iv.output, output, "IV test incremental(5) {} failed", i);
        }

        // Test that reset works as expected
        {
            let mut context = new(alg, iv.key);
            context = update(context, b"some arbitrary data");
            reset(&mut context, iv.key);
            context = update(context, iv.input);
            let output = finalize(context);
            assert_eq!(iv.output, output, "IV test reset {} failed", i);
        }

        {
            let mut context = new(alg, iv.key);
            context = update(context, b"some arbitrary data");
            reset(&mut context, iv.key);
            context = update(context, iv.input);
            let output = finalize_reset(&mut context, iv.key);
            assert_eq!(iv.output, output, "IV test finalize-reset {} failed", i);
            assert!(
                finalize(new(alg, iv.key)) == finalize(context),
                "context after finalize-reset not correct"
            );
        }
    }
}
