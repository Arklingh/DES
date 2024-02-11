#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

mod des;
use des::{des_alg, tdes_alg, Key};
use eframe::egui::{self, ViewportBuilder, ViewportCommand};
use eframe::egui::{Layout, RichText};
use eframe::Theme;
// use num_cpus;                     <- These will be used for multirhreading
// use rayon::ThreadPoolBuilder;     <-|
// use std::collections::BinaryHeap; <-|
// use std::sync::{Arc, Mutex};      <-|
use regex::Regex;
use std::io::{Read, Write};
use std::process;
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::runtime::Runtime;

const MIN_RES_WIN_WIDTH: f32 = 150.0;
const MIN_RES_WIN_HIGHT: f32 = 113.0;
const CHUNK_SIZE: usize = 128 * 1024; //128KB

/// An array of weak DES keys.
const WEAK_KEY: [u64; 4] = [
    0x0101010101010101,
    0xFEFEFEFEFEFEFEFE,
    0x1F1F1F1F0E0E0E0E,
    0xE0E0E0E0F1F1F1F1,
];

/// An array of semi-weak DES key pairs.
const SEMI_WEAK_KEY: [(u64, u64); 6] = [
    (0x01FE01FE01FE01FE, 0xFE01FE01FE01FE01),
    (0x1FE01FE01FE01FE0, 0xE0F1E0F1E0F1E0F1),
    (0x01E001E001F101F1, 0xE001E001F101F101),
    (0x1FFE1FFE0EFE0EFE, 0xFE1FFE1FFE0EFE0E),
    (0x011F011F010E010E, 0x1F011F010E010E01),
    (0xE0FEE0FEF1FEF1FE, 0xFEE0FEE0FEF1FEF1),
];

macro_rules! crypt_operation {
    ($algorithm:expr, $action:expr, $mode:expr, $input_data:expr, $keys:expr, $iv:expr, $prev_block:expr) => {
        match ($algorithm, $action, $mode) {
            (Algorithm::DES, Action::Encrypt, Mode::ECB) => {
                des_alg::ecb_encrypt($input_data, $keys)
            }
            (Algorithm::DES, Action::Decrypt, Mode::ECB) => {
                des_alg::ecb_decrypt($input_data, $keys)
            }
            (Algorithm::TDES_EEE3, Action::Encrypt, Mode::ECB) => {
                tdes_alg::EEE3::ecb_encrypt($input_data, $keys)
            }
            (Algorithm::TDES_EEE3, Action::Decrypt, Mode::ECB) => {
                tdes_alg::EEE3::ecb_decrypt($input_data, $keys)
            }
            (Algorithm::TDES_EDE3, Action::Encrypt, Mode::ECB) => {
                tdes_alg::EDE3::ecb_encrypt($input_data, $keys)
            }
            (Algorithm::TDES_EDE3, Action::Decrypt, Mode::ECB) => {
                tdes_alg::EDE3::ecb_decrypt($input_data, $keys)
            }
            (Algorithm::TDES_EEE2, Action::Encrypt, Mode::ECB) => {
                tdes_alg::EEE2::ecb_encrypt($input_data, $keys)
            }
            (Algorithm::TDES_EEE2, Action::Decrypt, Mode::ECB) => {
                tdes_alg::EEE2::ecb_decrypt($input_data, $keys)
            }
            (Algorithm::DES, Action::Encrypt, Mode::CBC) => {
                des_alg::cbc_encrypt($input_data, $keys, $iv, $prev_block)
            }
            (Algorithm::DES, Action::Decrypt, Mode::CBC) => {
                des_alg::cbc_decrypt($input_data, $keys, $iv, $prev_block)
            }
            (Algorithm::TDES_EEE3, Action::Encrypt, Mode::CBC) => {
                tdes_alg::EEE3::cbc_encrypt($input_data, $keys, $iv, $prev_block)
            }
            (Algorithm::TDES_EEE3, Action::Decrypt, Mode::CBC) => {
                tdes_alg::EEE3::cbc_decrypt($input_data, $keys, $iv, $prev_block)
            }
            (Algorithm::TDES_EDE3, Action::Encrypt, Mode::CBC) => {
                tdes_alg::EDE3::cbc_encrypt($input_data, $keys, $iv, $prev_block)
            }
            (Algorithm::TDES_EDE3, Action::Decrypt, Mode::CBC) => {
                tdes_alg::EDE3::cbc_decrypt($input_data, $keys, $iv, $prev_block)
            }
            (Algorithm::TDES_EEE2, Action::Encrypt, Mode::CBC) => {
                tdes_alg::EEE2::cbc_encrypt($input_data, $keys, $iv, $prev_block)
            }
            (Algorithm::TDES_EEE2, Action::Decrypt, Mode::CBC) => {
                tdes_alg::EEE2::cbc_decrypt($input_data, $keys, $iv, $prev_block)
            }

            _ => unreachable!(),
        }
    };
}

// #[tokio::main]
fn main() {
    let rt = Runtime::new().expect("Unable to create a Runtime");

    let _enter = rt.enter();

    let options = eframe::NativeOptions {
        viewport: ViewportBuilder {
            resizable: Some(false),
            inner_size: Some(egui::vec2(300.0, 650.0)),
            maximize_button: Some(false),
            ..Default::default()
        },
        default_theme: Theme::Dark,
        ..Default::default()
    };

    let _ = eframe::run_native(
        "DES v.0.6.0",
        options,
        Box::new(|_cc| Box::<MyApp>::default()),
    );
}

#[derive(PartialEq, Copy)]
enum Mode {
    ECB,
    CBC,
}

impl Default for Mode {
    fn default() -> Self {
        Mode::ECB
    }
}

impl Clone for Mode {
    fn clone(&self) -> Self {
        *self
    }
}

#[derive(PartialEq, Debug, Copy)]
enum Algorithm {
    DES,
    TDES_EEE3,
    TDES_EDE3,
    TDES_EEE2,
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::DES
    }
}

impl Clone for Algorithm {
    fn clone(&self) -> Self {
        *self
    }
}

#[derive(Default, Clone)]
struct KeysStr {
    key1: String,
    key2: String,
    key3: String,
}

#[derive(PartialEq, Copy)]
enum Action {
    Encrypt,
    Decrypt,
}

impl Default for Action {
    fn default() -> Self {
        Action::Encrypt
    }
}

impl Clone for Action {
    fn clone(&self) -> Self {
        *self
    }
}

struct MyApp {
    input_file: String,
    output_file: String,
    algorithm: Algorithm,
    mode: Mode,
    action: Action,
    raw_keys: KeysStr,
    keys: Vec<Key>,
    raw_iv: String,
    iv: [u8; 8],
    num_threads: usize,
    result_time: Duration,
    asnc: bool,
    tx: Sender<Duration>,
    rx: Receiver<Duration>,
    processing: bool,
}

impl Default for MyApp {
    fn default() -> Self {
        let (tx, rx) = std::sync::mpsc::channel();

        Self {
            input_file: "".to_string(),
            output_file: "".to_string(),
            algorithm: Algorithm::DES,
            mode: Mode::ECB,
            action: Action::Encrypt,
            raw_keys: KeysStr {
                key1: "".to_string(),
                key2: "".to_string(),
                key3: "".to_string(),
            },
            keys: vec![[0; 8]],
            raw_iv: "".to_string(),
            iv: [0; 8],
            num_threads: 1,
            result_time: Duration::new(0, 0),
            asnc: false,
            tx,
            rx,
            processing: false,
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            let layout = Layout::from_main_dir_and_cross_align(
                egui::Direction::LeftToRight,
                eframe::emath::Align::Min,
            );
            let popup_id = ui.make_persistent_id("Result Popup");
            if let Ok(time) = self.rx.try_recv() {
                self.result_time = time;
                self.processing = false;
                ui.with_layout(layout, |ui| {
                    ui.memory_mut(|mem| mem.open_popup(popup_id));
                });
            }

            ui.vertical_centered(|ui| {
                ui.label(egui::RichText::new("Select files").heading())
                    .highlight();
            });

            let input_button_text = egui::RichText::new("Input file...").size(14.0);
            ui.horizontal(|ui| {
                let input_button = ui.add_sized([90.0, 30.0], egui::Button::new(input_button_text));
                ui.weak("Alt+O");
                if input_button.clicked()
                    || ui.input(|i| i.modifiers.alt && i.key_pressed(egui::Key::O))
                {
                    if let Some(path) = rfd::FileDialog::new().pick_file() {
                        self.input_file = path.display().to_string();
                    }
                }
            });

            ui.horizontal(|ui| {
                ui.style_mut().wrap = Some(true);
                ui.label("Input file:");
                ui.monospace(&self.input_file);
            });

            ui.label("");

            ui.horizontal(|ui| {
                let output_button_text = egui::RichText::new("Output file...").size(14.0);
                let output_button =
                    ui.add_sized([90.0, 30.0], egui::Button::new(output_button_text));
                ui.weak("Alt+S");
                if output_button.clicked()
                    || ui.input(|i| i.modifiers.alt && i.key_pressed(egui::Key::S))
                {
                    if let Some(path) = rfd::FileDialog::new().save_file() {
                        self.output_file = path.display().to_string();
                    }
                }
            });

            ui.horizontal(|ui| {
                ui.style_mut().wrap = Some(true);
                ui.label("Output file:");
                ui.monospace(&self.output_file);
            });

            ui.vertical_centered(|ui| {
                ui.label(egui::RichText::new("Select options").heading())
                    .highlight();

                ui.label("");

                ui.horizontal(|ui| {
                    ui.label("Select the algorithm");
                    egui::ComboBox::from_label(format!(""))
                        .selected_text(format!("{:?}", self.algorithm))
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.algorithm, Algorithm::DES, "DES");
                            ui.selectable_value(
                                &mut self.algorithm,
                                Algorithm::TDES_EDE3,
                                "TDES-EDE3",
                            );
                            ui.selectable_value(
                                &mut self.algorithm,
                                Algorithm::TDES_EEE3,
                                "TDES-EEE3",
                            );
                            ui.selectable_value(
                                &mut self.algorithm,
                                Algorithm::TDES_EEE2,
                                "TDES-EEE2",
                            );
                        });
                });

                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label("\nChoose execution mode:");
                        ui.radio_value(&mut self.mode, Mode::ECB, "ECB");
                        ui.radio_value(&mut self.mode, Mode::CBC, "CBC");
                    });

                    ui.vertical(|ui| {
                        ui.label("\nChoose action:");
                        ui.radio_value(&mut self.action, Action::Encrypt, "Encrypt");
                        ui.radio_value(&mut self.action, Action::Decrypt, "Decrypt");
                    });
                });

                ui.label("");

                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("Input keys").heading())
                        .highlight();
                });

                if self.algorithm == Algorithm::DES {
                    ui.vertical(|ui| {
                        ui.label("Enter the key(16-digit hex number):");
                        let key = ui.add(
                            egui::TextEdit::singleline(&mut self.raw_keys.key1).hint_text("Key"),
                        );
                        if key.changed() {
                            if !check_hex_input(&self.raw_keys.key1)
                                || self.raw_keys.key1.len() > 16
                            {
                                self.raw_keys.key1 = self
                                    .raw_keys
                                    .key1
                                    .chars()
                                    .filter(|c| check_hex_input(&c.to_string()))
                                    .collect();
                            }
                            if self.raw_keys.key1.len() > 16 {
                                self.raw_keys.key1.truncate(16);
                            }
                        }
                    });
                } else if self.algorithm == Algorithm::TDES_EEE3
                    || self.algorithm == Algorithm::TDES_EDE3
                    || self.algorithm == Algorithm::TDES_EEE2
                {
                    ui.vertical(|ui| {
                        ui.label("Enter the first key(16-digit hex number):");
                        let key1 = ui.add(
                            egui::TextEdit::singleline(&mut self.raw_keys.key1).hint_text("Key 1"),
                        );
                        if key1.changed() {
                            if !check_hex_input(&self.raw_keys.key1)
                                || self.raw_keys.key1.len() > 16
                            {
                                self.raw_keys.key1 = self
                                    .raw_keys
                                    .key1
                                    .chars()
                                    .filter(|c| check_hex_input(&c.to_string()))
                                    .collect();
                            }
                            if self.raw_keys.key1.len() > 16 {
                                self.raw_keys.key1.truncate(16);
                            }
                        }
                        ui.label("\nEnter the second key:");
                        let key2 = ui.add(
                            egui::TextEdit::singleline(&mut self.raw_keys.key2).hint_text("Key 2"),
                        );
                        if key2.changed() {
                            if !check_hex_input(&self.raw_keys.key2)
                                || self.raw_keys.key2.len() > 16
                            {
                                self.raw_keys.key2 = self
                                    .raw_keys
                                    .key2
                                    .chars()
                                    .filter(|c| check_hex_input(&c.to_string()))
                                    .collect();
                            }
                            if self.raw_keys.key2.len() > 16 {
                                self.raw_keys.key2.truncate(16);
                            }
                        }
                        ui.label("\nEnter the third key:");
                        let key3 = ui.add(
                            egui::TextEdit::singleline(&mut self.raw_keys.key3).hint_text("Key 3"),
                        );
                        if key3.changed() {
                            if !check_hex_input(&self.raw_keys.key3)
                                || self.raw_keys.key3.len() > 16
                            {
                                self.raw_keys.key3 = self
                                    .raw_keys
                                    .key3
                                    .chars()
                                    .filter(|c| check_hex_input(&c.to_string()))
                                    .collect();
                            }
                            if self.raw_keys.key3.len() > 16 {
                                self.raw_keys.key3.truncate(16);
                            }
                        }
                    });
                }

                if self.mode == Mode::ECB {
                } else if self.mode == Mode::CBC {
                    ui.vertical(|ui| {
                        ui.label("\nEnter the IV(16-digit hex number):");
                        let iv_key =
                            ui.add(egui::TextEdit::singleline(&mut self.raw_iv).hint_text("IV"));
                        if iv_key.changed() {
                            if !check_hex_input(&self.raw_iv) || self.raw_iv.len() > 16 {
                                self.raw_iv = self
                                    .raw_iv
                                    .chars()
                                    .filter(|c| check_hex_input(&c.to_string()))
                                    .collect();
                            }
                            if self.raw_iv.len() > 16 {
                                self.raw_iv.truncate(16);
                            }
                        }
                    });
                }
            });

            /*
            if self.mode == Mode::ECB {
                 ui.label("Select a number of threads to be used");
                 ui.add(egui::Slider::new(
                     &mut self.num_threads,
                     1..=num_cpus::get() - 1,
                ));
            } else {
                self.num_threads = 1;
            }
            NOT IMPLEMENTED YET!
            */

            ui.label("\n");
            if self.mode == Mode::ECB {
                ui.checkbox(&mut self.asnc, "Asynchronous mode");
            } else {
                self.asnc = false;
            }
            ui.label("\n");

            ui.horizontal(|ui| {
                let keys_are_empty = self.raw_keys.key1.is_empty()
                    || !check_len(&self.raw_keys.key1)
                    || (matches!(
                        self.algorithm,
                        Algorithm::TDES_EEE3 | Algorithm::TDES_EDE3 | Algorithm::TDES_EEE2
                    ) && (self.raw_keys.key2.is_empty()
                        || !check_len(&self.raw_keys.key2)
                        || self.raw_keys.key3.is_empty()
                        || !check_len(&self.raw_keys.key3)))
                    || (self.mode == Mode::CBC
                        && (self.raw_iv.is_empty() || !check_len(&self.raw_iv)));

                let essential_params_are_empty =
                    keys_are_empty || self.input_file.is_empty() || self.output_file.is_empty();

                let mut keys_valid = !essential_params_are_empty;

                let start_button_text = egui::RichText::new("Start").size(15.0);
                let start_button = ui.add_enabled(
                    keys_valid && !self.processing,
                    egui::Button::new(start_button_text)
                        .min_size(eframe::epaint::Vec2 { x: 90.0, y: 30.0 })
                        .shortcut_text("Ctrl+S"),
                );

                ui.label("                            ");

                let exit_button_text = egui::RichText::new("Exit").size(15.0);
                let exit_button = ui.add_enabled(
                    !self.processing,
                    egui::Button::new(exit_button_text)
                        .min_size(eframe::epaint::Vec2 { x: 90.0, y: 30.0 })
                        .shortcut_text("Ctrl+E"),
                );

                ui.label("\n");

                if self.processing {
                    let spin = ui.label("Processing...");
                    ui.add(egui::widgets::Spinner::new()).labelled_by(spin.id);
                }

                let weak_key_error_popup = ui.make_persistent_id("Weak Key Error Popup");
                let bad_key_error_popup = ui.make_persistent_id("Bad Key Error Popup");
                let pos = if self.algorithm == Algorithm::TDES_EDE3
                    || self.algorithm == Algorithm::TDES_EEE3
                    || self.algorithm == Algorithm::TDES_EEE2
                {
                    egui::AboveOrBelow::Above
                } else {
                    egui::AboveOrBelow::Below
                };

                if start_button.clicked()
                    || ui.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::S))
                {
                    self.processing = true;

                    match self.algorithm {
                        Algorithm::DES => {
                            let parsed_key = parse_key(&self.raw_keys.key1);
                            if let Ok(key) = parsed_key {
                                if is_weak_key(&u64_from_bytes(&key[0])) {
                                    ui.memory_mut(|mem| {
                                        mem.open_popup(weak_key_error_popup);
                                    });
                                    keys_valid = false;
                                } else {
                                    self.keys = key;
                                }
                            } else {
                                ui.memory_mut(|mem| {
                                    mem.open_popup(bad_key_error_popup);
                                });
                                keys_valid = false;
                            };
                        }
                        Algorithm::TDES_EEE3 | Algorithm::TDES_EDE3 | Algorithm::TDES_EEE2 => {
                            let parsed_key1 = parse_key(&self.raw_keys.key1);
                            let parsed_key2 = parse_key(&self.raw_keys.key2);
                            let parsed_key3 = parse_key(&self.raw_keys.key3);

                            if let (Ok(key1), Ok(key2), Ok(key3)) =
                                (parsed_key1, parsed_key2, parsed_key3)
                            {
                                if is_weak_key(&u64_from_bytes(&key1[0]))
                                    || is_weak_key(&u64_from_bytes(&key2[0]))
                                    || is_weak_key(&u64_from_bytes(&key3[0]))
                                    || !is_semi_weak(&[key1[0], key2[0], key3[0]])
                                {
                                    ui.memory_mut(|mem| {
                                        mem.open_popup(weak_key_error_popup);
                                    });
                                    keys_valid = false;
                                } else {
                                    self.keys.push(key1[0]);
                                    self.keys.push(key2[0]);
                                    self.keys.push(key3[0]);
                                }
                            } else {
                                ui.memory_mut(|mem| {
                                    mem.open_popup(bad_key_error_popup);
                                });
                                keys_valid = false;
                            }
                        }
                    }
                    if keys_valid {
                        if self.mode == Mode::CBC {
                            self.iv = parse_iv(&self.raw_iv);
                        }

                        send(
                            self.input_file.clone(),
                            self.output_file.clone(),
                            self.algorithm.clone(),
                            self.action.clone(),
                            self.mode.clone(),
                            self.keys.clone(),
                            self.iv.clone(),
                            self.num_threads.clone(),
                            self.asnc.clone(),
                            self.tx.clone(),
                            ctx.clone(),
                        );
                    }
                };

                if exit_button.clicked()
                    || ui.input(|i| i.modifiers.ctrl && i.key_pressed(egui::Key::E))
                {
                    ctx.send_viewport_cmd(ViewportCommand::Close);
                }

                let result_box = RichText::new(format!(
                    "Time spent encrypting/decrypting: {}.{:03} seconds",
                    self.result_time.as_secs(),
                    self.result_time.subsec_millis(),
                ));

                egui::containers::popup::popup_above_or_below_widget(
                    &ui,
                    weak_key_error_popup,
                    &start_button,
                    pos,
                    |ui| {
                        ui.set_min_width(MIN_RES_WIN_WIDTH);
                        ui.set_min_height(MIN_RES_WIN_HIGHT);
                        ui.label(format!(
                            "Weak or semi-weak key(s) used! Use more secure key!"
                        ))
                        .highlight();
                    },
                );
                egui::containers::popup::popup_above_or_below_widget(
                    &ui,
                    popup_id,
                    &start_button,
                    pos,
                    |ui| {
                        ui.set_min_width(MIN_RES_WIN_WIDTH);
                        ui.set_min_height(MIN_RES_WIN_HIGHT);
                        ui.label(result_box);
                    },
                );
            });
        });
    }
}

fn send(
    input_file: String,
    output_file: String,
    algorithm: Algorithm,
    action: Action,
    mode: Mode,
    keys: Vec<Key>,
    iv: [u8; 8],
    num_threads: usize,
    asnc: bool,
    tx: Sender<Duration>,
    ctx: egui::Context,
) {
    if asnc {
        tokio::spawn(async move {
            let res = process_async(
                input_file,
                output_file,
                algorithm,
                action,
                mode,
                keys,
                iv,
                num_threads,
            )
            .await;
            if let Err(e) = tx.send(res) {
                eprintln!("Error sending result through channel: {}", e);
            }

            ctx.request_repaint();
        });
    } else {
        tokio::task::spawn_blocking(move || {
            let res = process(
                input_file,
                output_file,
                algorithm,
                action,
                mode,
                keys,
                iv,
                num_threads,
            );
            if let Err(e) = tx.send(res) {
                eprintln!("Error sending result through channel: {}", e);
            };

            ctx.request_repaint();
        });
    }
}

fn process(
    input_file: String,
    output_file: String,
    algorithm: Algorithm,
    action: Action,
    mode: Mode,
    keys: Vec<Key>,
    iv: [u8; 8],
    num_threads: usize,
) -> Duration {
    let file = std::fs::File::open(&input_file.as_str()).expect("Error opening a file :(");
    let mut reader = std::io::BufReader::with_capacity(CHUNK_SIZE, file);
    let mut buffer = vec![0; CHUNK_SIZE];
    let mut prev_block: Option<Vec<u8>> = None;
    let mut padded = false;
    let mut input_data: &[u8];
    let mut padding_size: usize = 0;
    let mut num_padded = 0;
    let mut chunk_result = Vec::new();

    let mut file = std::fs::File::create(&output_file).unwrap();

    let start_time = Instant::now(); // Record the start time.

    while let Ok(size) = reader.read(&mut buffer) {
        if size == 0 {
            break;
        }
        if action == Action::Encrypt {
            padding_size = 8 - (size % 8);
            if padding_size != 8 {
                padded = true;
                buffer.extend(vec![0; padding_size]);
                input_data = &buffer[..size + padding_size];
            } else {
                input_data = &buffer[..size];
            };
        } else {
            input_data = &buffer[..size];
        }
        if action == Action::Decrypt {
            num_padded = input_data[input_data.len() - 1];
        }
        (chunk_result, prev_block) =
            crypt_operation!(algorithm, action, mode, input_data, &keys, &iv, prev_block);

        if action == Action::Decrypt && size % 8 != 0 {
            let _ = chunk_result.pop();
            chunk_result.truncate(size - (num_padded as usize + 1));
        }
        if padded {
            chunk_result.push(padding_size as u8);
        }
        if let Err(e) = file.write_all(&chunk_result) {
            eprintln!("Uh-oh, big problemo!: {e}");
        };
    }

    let crypt_time = start_time.elapsed();

    crypt_time
}

async fn process_async(
    input_file: String,
    output_file: String,
    algorithm: Algorithm,
    action: Action,
    mode: Mode,
    keys: Vec<Key>,
    iv: [u8; 8],
    num_threads: usize,
) -> Duration {
    let file = tokio::fs::File::open(&input_file.as_str())
        .await
        .expect("Error opening a file :(");
    let mut reader = tokio::io::BufReader::with_capacity(CHUNK_SIZE, file);
    let mut buffer = vec![0; CHUNK_SIZE];
    let mut padded = false;
    let mut input_data: &[u8];
    let mut padding_size: usize = 0;
    let mut num_padded = 0;
    let mut chunk_result = Vec::new();
    let mut prev_block: Option<Vec<u8>> = None;

    let mut file = tokio::fs::File::create(&output_file).await.unwrap();

    let start_time = Instant::now(); // Record the start time.

    while let Ok(size) = reader.read(&mut buffer).await {
        if size == 0 {
            break;
        }
        if action == Action::Encrypt {
            padding_size = 8 - (size % 8);
            if padding_size != 8 {
                padded = true;
                buffer.extend(vec![0; padding_size]);
                input_data = &buffer[..size + padding_size];
            } else {
                input_data = &buffer[..size];
            };
        } else {
            input_data = &buffer[..size];
        }
        if action == Action::Decrypt {
            num_padded = input_data[input_data.len() - 1];
        }
        (chunk_result, prev_block) =
            crypt_operation!(algorithm, action, mode, input_data, &keys, &iv, prev_block);

        if action == Action::Decrypt && size % 8 != 0 {
            let _ = chunk_result.pop();
            chunk_result.truncate(size - (num_padded as usize + 1));
        }
        if padded {
            chunk_result.push(padding_size as u8);
        }
        if let Err(e) = file.write_all(&chunk_result).await {
            eprintln!("Uh-oh, big problemo!: {e}");
        };
    }

    let crypt_time = start_time.elapsed();

    crypt_time
}

/// Collects a key_str String variable and returns a 16-digit hex Key.
///
/// # Arguments
///
/// * `key_str` - The key as a 16-character hexadecimal string.
///
/// # Returns
///
/// A `Result` containing a vector of Keys if successful, otherwise an error message.
fn parse_key(key_str: &String) -> Result<Vec<Key>, &'static str> {
    let mut key = [0; 8];

    if key_str.len() == 16 {
        for (i, chunk) in key_str.as_bytes().chunks(2).enumerate() {
            key[i] = u8::from_str_radix(std::str::from_utf8(chunk).expect("Invalid UTF-8"), 16)
                .expect("Invalid hex format");
        }
        Ok(vec![key])
    } else {
        Err("Key must be valid 16-digit hex number!")
    }
}

/// Collects an iv_str String variable and returns a 16-digit hex Key.
///
/// # Arguments
///
/// * `iv_str` - The IV as a 16-character hexadecimal string.
///
/// # Returns
///
/// A `Result` containing an array of u8s (IV) if successful, otherwise an error message.
fn parse_iv(iv_str: &String) -> [u8; 8] {
    if iv_str.len() == 16 {
        let mut iv = [0; 8];
        for (i, chunk) in iv_str.as_bytes().chunks(2).enumerate() {
            iv[i] = u8::from_str_radix(std::str::from_utf8(chunk).expect("Invalid UTF-8"), 16)
                .expect("Invalid hex format");
        }
        iv
    } else {
        eprintln!("IV must be a 16-character hexadecimal string.");
        process::exit(1);
    }
}

/// Reads a line from standard input, trims it, and ensures it is a valid
/// 16-digit hex number.
///
/// # Arguments
///
/// * `input` - The input recieved from the user.
///
/// # Returns
///
/// Returns a true if input is valid 16-digit hex, false - otherwise.
fn check_hex_input(input: &String) -> bool {
    let hex_pattern = Regex::new(r"^[0-9A-Fa-f]{1,16}$").expect("Couldn't generate regex!");

    hex_pattern.is_match(&input.trim())
}

fn check_len(input: &String) -> bool {
    if input.len() < 16 {
        false
    } else {
        true
    }
}

fn is_weak_key(key: &u64) -> bool {
    // Check if the key is weak and return a boolean result
    WEAK_KEY.contains(key)
}

fn is_semi_weak(keys: &[Key; 3]) -> bool {
    for (key1, key2) in SEMI_WEAK_KEY {
        for i in 0..keys.len() {
            for j in 0..keys.len() {
                if i != j && (u64_from_bytes(&keys[i]) == key1 && u64_from_bytes(&keys[j]) == key2)
                {
                    eprintln!("Semi-weak key!!! Try again!");
                    return false;
                }
            }
        }
    }
    true
}

fn u64_from_bytes(bytes: &[u8]) -> u64 {
    if bytes.len() != 8 {
        panic!("Масив байтів повинен містити точно 8 байтів для конвертації в u64");
    }

    let mut result: u64 = 0;
    for i in 0..8 {
        result |= (bytes[i] as u64) << (56 - 8 * i);
    }

    result
}
