#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), deny(warnings))] // Forbid warnings in release builds
#![warn(clippy::all, rust_2018_idioms)]

use aes::Aes256;
use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
use serde::Deserialize;

mod app;
pub use app::LaravelDecryptApp;

pub type Aes256Cbc = Cbc<Aes256, Pkcs7>;

#[derive(Deserialize, Debug)]
pub struct LaravelEncryptedData {
    iv: String,
    value: String,
    #[serde(rename = "mac")]
    _mac: String,
}

impl LaravelEncryptedData {
    fn get_value(&self) -> Result<Vec<u8>, String> {
        match base64::decode(&self.value) {
            Ok(v) => Ok(v),
            Err(e) => Err(e.to_string()),
        }
    }
    fn get_iv(&self) -> Result<Vec<u8>, String> {
        match base64::decode(&self.iv) {
            Ok(v) => Ok(v),
            Err(e) => Err(e.to_string()),
        }
    }
}

pub fn decrypt(key: Vec<u8>, ciphertext: Vec<u8>, iv: Vec<u8>) -> Result<String, String> {
    let cipher = match Aes256Cbc::new_from_slices(&key, &iv) {
        Ok(v) => v,
        Err(e) => return Err(e.to_string()),
    };
    let data = match cipher.decrypt_vec(&ciphertext) {
        Ok(v) => v,
        Err(e) => return Err(e.to_string()),
    };
    Ok(String::from_utf8_lossy(&data).to_string())
}

pub fn parse_ciphertext(ciphertext: &str) -> Result<LaravelEncryptedData, String> {
    let payload = match base64::decode(ciphertext) {
        Ok(v) => v,
        Err(_) => return Err("failed to decode base64".to_owned()),
    };
    match serde_json::from_slice(&payload) {
        Ok(v) => Ok(v),
        Err(e) => Err(e.to_string()),
    }
}

// ----------------------------------------------------------------------------
// When compiling for web:

#[cfg(target_arch = "wasm32")]
use eframe::wasm_bindgen::{self, prelude::*};

/// This is the entry-point for all the web-assembly.
/// This is called once from the HTML.
/// It loads the app, installs some callbacks, then returns.
/// You can add more callbacks like this if you want to call in to your code.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn start(canvas_id: &str) -> Result<(), eframe::wasm_bindgen::JsValue> {
    let app = LaravelDecryptApp::default();
    eframe::start_web(canvas_id, Box::new(app))
}
