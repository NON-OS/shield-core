//! For a debug build only: a panic is printed to the console before the abort, which otherwise
//! reaches the page as a bare `unreachable`. Off in a release, since a message can name a value.

use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn error(text: &str);
}

#[wasm_bindgen]
pub fn report_panics() {
    std::panic::set_hook(Box::new(|info| error(&info.to_string())));
}
