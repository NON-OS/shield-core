//! The binding generator, run by the shell build scripts to emit the Kotlin and
//! Swift bindings from the library's own metadata.

fn main() {
    uniffi::uniffi_bindgen_main()
}
