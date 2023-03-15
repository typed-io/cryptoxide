## Changing slice by array reference

For slice to array reference changes of the form:

```
fn function(value: &[u8]) { ... }
```

to:

```
fn function(value: &[u8; 12]) { ... }
```

In the case of the caller using array of the right size already,
no changes need to be done. But, when the caller is using a subslice,
one can use the following construction, from:

```
fn caller() {
   let slice = &[....];
   function(&slice[0..12]);
}
```

to:

```
use core::convert::TryFrom; // not-necessary in latest rust edition
fn caller() {
   let slice = &[....];
   function(<&[u8; 12]>::try_from(&slice[0..12]).unwrap());
}
```

Note the .unwrap() is just one way to (not) handle the error, and the caller
should integrate the failing `try_from` case with the error handling
conventions of the caller code.
