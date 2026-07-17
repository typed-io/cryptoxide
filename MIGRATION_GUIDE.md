## Changing slice by array reference

For slice to array reference changes of the form:

```rust
fn function(value: &[u8]) { .... }
```

to:

```rust
fn function(value: &[u8; 12]) { .... }
```

In the case of the caller using array of the right size already,
no changes need to be done. But, when the caller is using a subslice,
one can use the following construction, from:

```rust
fn caller() {
   let slice = &[....];
   function(&slice[0..12]);
}
```

to:

```rust
use core::convert::TryFrom; // not-necessary in latest rust edition
fn caller() {
   let slice = &[....];
   function(<&[u8; 12]>::try_from(&slice[0..12]).unwrap());
}
```

Note the .unwrap() is just one way to (not) handle the error, and the caller
should integrate the failing `try_from` case with the error handling
conventions of the caller code.

## Deprecation of the Digest and Mac traits

Digest trait is going away, in favor of using directly the module in the `hashing` module.

* `Digest`:
  * `input` become `update_mut`.
  * `result` become `finalize`.
  * `raw_result` become `finalize_at`.
  * `result_str` has no equivalent, instead use `finalize` and your favorite hex producing to get the same result.

The new Hashing APIs use a more functional approach and generally use an object
consume approach (using rust's affine type), to prevent having to store a
finalized boolean and the result of the algorithm in itself. The end result is
marginally smaller data structure and a cleaner API.
