use eframe::egui;

use crate::{decrypt, parse_ciphertext};

/// We derive Deserialize/Serialize so we can persist app state on shutdown.
#[cfg_attr(feature = "persistence", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "persistence", serde(default))] // if we add new fields, give them default values when deserializing old state
pub struct LaravelDecryptApp {
    cipherkey: String,
    ciphertext: String,
    result: String,
}

impl Default for LaravelDecryptApp {
    fn default() -> Self {
        Self {
            cipherkey: "input your cipher key".to_owned(),
            ciphertext: "input encrypted value".to_owned(),
            result: "result".to_owned(),
        }
    }
}

impl LaravelDecryptApp {
    /// Called once before the first frame.
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        // This is also where you can customize the look and feel of egui using
        // `cc.egui_ctx.set_visuals` and `cc.egui_ctx.set_fonts`.

        // Load previous app state (if any).
        // Note that you must enable the `persistence` feature for this to work.
        #[cfg(feature = "persistence")]
        if let Some(storage) = _cc.storage {
            return eframe::get_value(storage, eframe::APP_KEY).unwrap_or_default();
        }

        Default::default()
    }
}

impl eframe::App for LaravelDecryptApp {
    /// Called by the framework to save state before shutdown.
    /// Note that you must enable the `persistence` feature for this to work.
    #[cfg(feature = "persistence")]
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, eframe::APP_KEY, self);
    }

    /// Called each time the UI needs repainting, which may be many times per second.
    /// Put your widgets into a `SidePanel`, `TopPanel`, `CentralPanel`, `Window` or `Area`.
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let Self {
            cipherkey,
            ciphertext,
            result,
        } = self;

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Laravel Decrypt");
            ui.hyperlink("https://github.com/sakti/laravel_decrypt");
            ui.add(egui::github_link_file!(
                "https://github.com/sakti/laravel_decrypt/tree/master/",
                "Source code."
            ));
            ui.horizontal(|ui| {
                ui.label("Cipher Key: ");
                ui.text_edit_multiline(cipherkey);
            });

            ui.horizontal(|ui| {
                ui.label("Ciphertext: ");
                ui.text_edit_multiline(ciphertext);
            });

            if ui.button("Decrypt").clicked() {
                if cipherkey.is_empty() {
                    *result = "err: cipher key is empty".to_owned();
                    return;
                }
                if ciphertext.is_empty() {
                    *result = "err: ciphertext is empty".to_owned();
                    return;
                }
                let key = match base64::decode(cipherkey) {
                    Ok(v) => v,
                    Err(e) => {
                        *result = e.to_string();
                        return;
                    }
                };

                let cipherobj = parse_ciphertext(ciphertext);
                if cipherobj.is_err() {
                    *result = cipherobj.err().unwrap();
                    return;
                }
                let cipherobj = cipherobj.unwrap();
                let value = cipherobj.get_value();
                if value.is_err() {
                    *result = value.err().unwrap();
                    return;
                }
                let value = value.unwrap();
                let iv = cipherobj.get_iv();
                if iv.is_err() {
                    *result = iv.err().unwrap();
                    return;
                }
                let iv = iv.unwrap();
                let plaintext = match decrypt(key, value, iv) {
                    Ok(v) => v,
                    Err(e) => {
                        *result = e;
                        return;
                    }
                };
                *result = plaintext;
            }

            ui.horizontal(|ui| {
                ui.label("Plaintext: ");
                ui.label(result.clone());
                if ui.button("📋").on_hover_text("Click to copy").clicked() {
                    ui.ctx().copy_text(result.to_owned());
                }
            });

            egui::warn_if_debug_build(ui);
        });
    }
}
