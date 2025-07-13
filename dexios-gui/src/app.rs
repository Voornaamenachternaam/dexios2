use eframe::egui;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

use dexios_core::primitives::Algorithm;
use dexios_core::header::HashingAlgorithm;

use crate::secure_string::SecureString;
use crate::operations::{
    AsyncOperationHandler, OperationStatus, OperationMessage,
    EncryptRequest, DecryptRequest
};
use crate::ui;

/// Перечисление вкладок приложения
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppTab {
    Encrypt,
    Decrypt,
    Pack,
    Unpack,
    Tools,
}

impl Default for AppTab {
    fn default() -> Self {
        Self::Encrypt
    }
}

/// Состояние вкладки шифрования
#[derive(Clone)]
pub struct EncryptState {
    pub input_file: Option<PathBuf>,
    pub output_file: Option<PathBuf>,
    pub password: SecureString,
    pub confirm_password: SecureString,
    
    // Настройки шифрования
    pub algorithm: Algorithm,
    pub hash_algorithm: HashingAlgorithm,
    pub generate_passphrase: bool,
    pub passphrase_words: i32,
    
    // Дополнительные опции
    pub use_keyfile: bool,
    pub keyfile_path: Option<PathBuf>,
    pub detached_header: bool,
    pub header_path: Option<PathBuf>,
    pub secure_erase: bool,
    pub erase_passes: i32,
    pub calculate_hash: bool,
}

impl Default for EncryptState {
    fn default() -> Self {
        Self {
            input_file: None,
            output_file: None,
            password: SecureString::new(),
            confirm_password: SecureString::new(),
            algorithm: Algorithm::XChaCha20Poly1305,
            hash_algorithm: HashingAlgorithm::Blake3Balloon(dexios_core::header::BLAKE3BALLOON_LATEST),
            generate_passphrase: false,
            passphrase_words: 7,
            use_keyfile: false,
            keyfile_path: None,
            detached_header: false,
            header_path: None,
            secure_erase: false,
            erase_passes: 1,
            calculate_hash: false,
        }
    }
}

/// Состояние вкладки дешифрования
#[derive(Clone)]
pub struct DecryptState {
    pub input_file: Option<PathBuf>,
    pub output_file: Option<PathBuf>,
    pub password: SecureString,
    
    // Настройки
    pub use_keyfile: bool,
    pub keyfile_path: Option<PathBuf>,
    pub detached_header: bool,
    pub header_path: Option<PathBuf>,
    pub secure_erase: bool,
    pub erase_passes: i32,
    pub calculate_hash: bool,
}

impl Default for DecryptState {
    fn default() -> Self {
        Self {
            input_file: None,
            output_file: None,
            password: SecureString::new(),
            use_keyfile: false,
            keyfile_path: None,
            detached_header: false,
            header_path: None,
            secure_erase: false,
            erase_passes: 1,
            calculate_hash: false,
        }
    }
}

/// Настройки приложения
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub default_input_dir: Option<PathBuf>,
    pub default_output_dir: Option<PathBuf>,
    pub theme: Theme,
    pub font_size: f32,
    pub auto_generate_output_path: bool,
    pub remember_recent_files: bool,
    pub confirm_destructive_operations: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Theme {
    Dark,
    Light,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            default_input_dir: None,
            default_output_dir: None,
            theme: Theme::Dark,
            font_size: 14.0,
            auto_generate_output_path: true,
            remember_recent_files: true,
            confirm_destructive_operations: true,
        }
    }
}

/// Главная структура приложения
pub struct DexiosApp {
    // Основное состояние
    pub current_tab: AppTab,
    
    // Состояния операций
    pub encrypt_state: EncryptState,
    pub decrypt_state: DecryptState,
    
    // Настройки
    pub settings: AppSettings,
    
    // Асинхронные операции
    pub operation_handler: AsyncOperationHandler,
    pub operation_status: OperationStatus,
    
    // UI состояние
    pub show_settings: bool,
    pub error_message: Option<String>,
    pub success_message: Option<String>,
}

impl Default for DexiosApp {
    fn default() -> Self {
        Self {
            current_tab: AppTab::default(),
            encrypt_state: EncryptState::default(),
            decrypt_state: DecryptState::default(),
            settings: AppSettings::default(),
            operation_handler: AsyncOperationHandler::new(),
            operation_status: OperationStatus::default(),
            show_settings: false,
            error_message: None,
            success_message: None,
        }
    }
}

impl DexiosApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Загрузка настроек из хранилища
        let settings = if let Some(storage) = cc.storage {
            eframe::get_value(storage, eframe::APP_KEY).unwrap_or_default()
        } else {
            AppSettings::default()
        };

        // Применение темы
        match settings.theme {
            Theme::Dark => cc.egui_ctx.set_visuals(egui::Visuals::dark()),
            Theme::Light => cc.egui_ctx.set_visuals(egui::Visuals::light()),
        }

        Self {
            settings,
            ..Default::default()
        }
    }

    /// Валидация ввода для шифрования
    pub fn validate_encrypt_input(&self) -> Result<(), String> {
        if self.encrypt_state.input_file.is_none() {
            return Err("Please select an input file".to_string());
        }
        
        if self.encrypt_state.output_file.is_none() {
            return Err("Please select an output file".to_string());
        }
        
        if self.encrypt_state.password.is_empty() && !self.encrypt_state.use_keyfile {
            return Err("Please enter a password or select a keyfile".to_string());
        }
        
        if self.encrypt_state.password != self.encrypt_state.confirm_password {
            return Err("Passwords do not match".to_string());
        }
        
        Ok(())
    }

    /// Валидация ввода для дешифрования
    pub fn validate_decrypt_input(&self) -> Result<(), String> {
        if self.decrypt_state.input_file.is_none() {
            return Err("Please select an input file".to_string());
        }
        
        if self.decrypt_state.output_file.is_none() {
            return Err("Please select an output file".to_string());
        }
        
        if self.decrypt_state.password.is_empty() && !self.decrypt_state.use_keyfile {
            return Err("Please enter a password or select a keyfile".to_string());
        }
        
        Ok(())
    }

    /// Запуск операции шифрования
    pub fn start_encrypt_operation(&mut self) {
        match self.validate_encrypt_input() {
            Ok(_) => {
                let request = EncryptRequest {
                    input_file: self.encrypt_state.input_file.clone().unwrap(),
                    output_file: self.encrypt_state.output_file.clone().unwrap(),
                    password: self.encrypt_state.password.clone(),
                    algorithm: self.encrypt_state.algorithm,
                    hash_algorithm: self.encrypt_state.hash_algorithm,
                    keyfile_path: self.encrypt_state.keyfile_path.clone(),
                    detached_header: self.encrypt_state.detached_header,
                    header_path: self.encrypt_state.header_path.clone(),
                    secure_erase: self.encrypt_state.secure_erase,
                    erase_passes: self.encrypt_state.erase_passes,
                    calculate_hash: self.encrypt_state.calculate_hash,
                };
                
                self.operation_status.is_running = true;
                self.operation_status.error = None;
                self.error_message = None;
                self.success_message = None;
                
                self.operation_handler.start_encrypt_operation(request);
            }
            Err(e) => {
                self.error_message = Some(e);
            }
        }
    }

    /// Запуск операции дешифрования
    pub fn start_decrypt_operation(&mut self) {
        match self.validate_decrypt_input() {
            Ok(_) => {
                let request = DecryptRequest {
                    input_file: self.decrypt_state.input_file.clone().unwrap(),
                    output_file: self.decrypt_state.output_file.clone().unwrap(),
                    password: self.decrypt_state.password.clone(),
                    keyfile_path: self.decrypt_state.keyfile_path.clone(),
                    detached_header: self.decrypt_state.detached_header,
                    header_path: self.decrypt_state.header_path.clone(),
                    secure_erase: self.decrypt_state.secure_erase,
                    erase_passes: self.decrypt_state.erase_passes,
                    calculate_hash: self.decrypt_state.calculate_hash,
                };
                
                self.operation_status.is_running = true;
                self.operation_status.error = None;
                self.error_message = None;
                self.success_message = None;
                
                self.operation_handler.start_decrypt_operation(request);
            }
            Err(e) => {
                self.error_message = Some(e);
            }
        }
    }

    /// Отрисовка меню бара
    fn draw_menu_bar(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Settings").clicked() {
                        self.show_settings = true;
                        ui.close_menu();
                    }
                    if ui.button("Exit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });

                ui.menu_button("Tools", |ui| {
                    if ui.button("Hash Files").clicked() {
                        self.current_tab = AppTab::Tools;
                        ui.close_menu();
                    }
                    if ui.button("Secure Erase").clicked() {
                        self.current_tab = AppTab::Tools;
                        ui.close_menu();
                    }
                });

                ui.menu_button("Help", |ui| {
                    if ui.button("About").clicked() {
                        ui.close_menu();
                    }
                });
            });
        });
    }

    /// Отрисовка панели вкладок
    fn draw_tabs(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.current_tab, AppTab::Encrypt, "🔒 Encrypt");
            ui.selectable_value(&mut self.current_tab, AppTab::Decrypt, "🔓 Decrypt");
            ui.selectable_value(&mut self.current_tab, AppTab::Pack, "📦 Pack");
            ui.selectable_value(&mut self.current_tab, AppTab::Unpack, "📂 Unpack");
            ui.selectable_value(&mut self.current_tab, AppTab::Tools, "🛠 Tools");
        });
        ui.separator();
    }

    /// Отрисовка вкладки шифрования
    fn draw_encrypt_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("File Encryption");
        ui.add_space(10.0);

        // Выбор файлов
        ui.group(|ui| {
            ui.label(egui::RichText::new("Files").strong());
            ui.separator();

            if ui::file_picker_field(ui, "Input file:", &mut self.encrypt_state.input_file, "Browse...") {
                if let Some(file) = rfd::FileDialog::new().pick_file() {
                    self.encrypt_state.input_file = Some(file);
                }
            }

            if ui::file_picker_field(ui, "Output file:", &mut self.encrypt_state.output_file, "Browse...") {
                if let Some(file) = rfd::FileDialog::new().save_file() {
                    self.encrypt_state.output_file = Some(file);
                }
            }
        });

        ui.add_space(10.0);

        // Настройки паролей
        ui.group(|ui| {
            ui.label(egui::RichText::new("Authentication").strong());
            ui.separator();

            if !self.encrypt_state.use_keyfile {
                ui::password_field(ui, "Password:", &mut self.encrypt_state.password);
                ui::password_field(ui, "Confirm password:", &mut self.encrypt_state.confirm_password);
            }

            ui.checkbox(&mut self.encrypt_state.use_keyfile, "Use keyfile instead of password");

            if self.encrypt_state.use_keyfile {
                if ui::file_picker_field(ui, "Keyfile:", &mut self.encrypt_state.keyfile_path, "Browse...") {
                    if let Some(file) = rfd::FileDialog::new().pick_file() {
                        self.encrypt_state.keyfile_path = Some(file);
                    }
                }
            }
        });

        ui.add_space(10.0);

        // Настройки алгоритмов
        ui.group(|ui| {
            ui.label(egui::RichText::new("Algorithm Settings").strong());
            ui.separator();

            ui.horizontal(|ui| {
                ui.label("Encryption:");
                let algorithm_text = match self.encrypt_state.algorithm {
                    Algorithm::XChaCha20Poly1305 => "XChaCha20-Poly1305",
                    Algorithm::Aes256Gcm => "AES-256-GCM",
                    Algorithm::DeoxysII256 => "Deoxys-II-256",
                };
                egui::ComboBox::from_id_salt("encryption_algorithm")
                    .selected_text(algorithm_text)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.encrypt_state.algorithm, Algorithm::XChaCha20Poly1305, "XChaCha20-Poly1305");
                        ui.selectable_value(&mut self.encrypt_state.algorithm, Algorithm::Aes256Gcm, "AES-256-GCM");
                    });
            });
        });

        ui.add_space(10.0);

        // Дополнительные опции
        ui::checkbox_group(ui, "Additional Options", |ui| {
            ui.checkbox(&mut self.encrypt_state.detached_header, "Store header separately");
            ui.checkbox(&mut self.encrypt_state.secure_erase, "Secure erase original file");
            ui.checkbox(&mut self.encrypt_state.calculate_hash, "Calculate hash of encrypted file");
        });

        ui.add_space(20.0);

        // Кнопка шифрования
        let encrypt_enabled = !self.operation_status.is_running;
        if ui.add_enabled(encrypt_enabled, egui::Button::new("🔒 Encrypt File").min_size(egui::vec2(120.0, 30.0))).clicked() {
            self.start_encrypt_operation();
        }

        if self.operation_status.is_running && ui.button("Cancel").clicked() {
            self.operation_handler.cancel_operation();
            self.operation_status.is_running = false;
        }
    }

    /// Отрисовка вкладки дешифрования
    fn draw_decrypt_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("File Decryption");
        ui.add_space(10.0);

        // Выбор файлов
        ui.group(|ui| {
            ui.label(egui::RichText::new("Files").strong());
            ui.separator();

            if ui::file_picker_field(ui, "Input file:", &mut self.decrypt_state.input_file, "Browse...") {
                if let Some(file) = rfd::FileDialog::new().pick_file() {
                    self.decrypt_state.input_file = Some(file);
                }
            }

            if ui::file_picker_field(ui, "Output file:", &mut self.decrypt_state.output_file, "Browse...") {
                if let Some(file) = rfd::FileDialog::new().save_file() {
                    self.decrypt_state.output_file = Some(file);
                }
            }
        });

        ui.add_space(10.0);

        // Настройки паролей
        ui.group(|ui| {
            ui.label(egui::RichText::new("Authentication").strong());
            ui.separator();

            if !self.decrypt_state.use_keyfile {
                ui::password_field(ui, "Password:", &mut self.decrypt_state.password);
            }

            ui.checkbox(&mut self.decrypt_state.use_keyfile, "Use keyfile instead of password");

            if self.decrypt_state.use_keyfile {
                if ui::file_picker_field(ui, "Keyfile:", &mut self.decrypt_state.keyfile_path, "Browse...") {
                    if let Some(file) = rfd::FileDialog::new().pick_file() {
                        self.decrypt_state.keyfile_path = Some(file);
                    }
                }
            }
        });

        ui.add_space(10.0);

        // Дополнительные опции
        ui::checkbox_group(ui, "Additional Options", |ui| {
            ui.checkbox(&mut self.decrypt_state.detached_header, "Use separate header file");
            ui.checkbox(&mut self.decrypt_state.secure_erase, "Secure erase encrypted file");
            ui.checkbox(&mut self.decrypt_state.calculate_hash, "Calculate hash of decrypted file");
        });

        ui.add_space(20.0);

        // Кнопка дешифрования
        let decrypt_enabled = !self.operation_status.is_running;
        if ui.add_enabled(decrypt_enabled, egui::Button::new("🔓 Decrypt File").min_size(egui::vec2(120.0, 30.0))).clicked() {
            self.start_decrypt_operation();
        }

        if self.operation_status.is_running && ui.button("Cancel").clicked() {
            self.operation_handler.cancel_operation();
            self.operation_status.is_running = false;
        }
    }

    /// Отрисовка статус-бара
    fn draw_status_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.operation_status.status);
                
                if self.operation_status.is_running {
                    ui.separator();
                    ui::progress_bar_with_text(ui, self.operation_status.progress, "");
                }
            });
        });
    }

    /// Отрисовка сообщений об ошибках и успехе
    fn draw_messages(&mut self, ui: &mut egui::Ui) {
        if let Some(error) = &self.error_message {
            ui::error_panel(ui, error);
            ui.add_space(10.0);
        }

        if let Some(success) = &self.success_message {
            ui::success_panel(ui, success);
            ui.add_space(10.0);
        }
    }
}

impl eframe::App for DexiosApp {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, eframe::APP_KEY, &self.settings);
    }

    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        // Обработка сообщений от асинхронных операций
        while let Ok(msg) = self.operation_handler.receiver.try_recv() {
            match msg {
                OperationMessage::Progress(p) => {
                    self.operation_status.progress = p;
                }
                OperationMessage::Status(s) => {
                    self.operation_status.status = s;
                }
                OperationMessage::Error(e) => {
                    self.operation_status.is_running = false;
                    self.operation_status.error = Some(e.clone());
                    self.error_message = Some(e);
                }
                OperationMessage::Complete(s) => {
                    self.operation_status.is_running = false;
                    self.operation_status.progress = 1.0;
                    self.success_message = Some(s);
                }
            }
        }

        // Автоматическая перерисовка при работающих операциях
        if self.operation_status.is_running {
            ctx.request_repaint();
        }

        // Отрисовка меню
        self.draw_menu_bar(ctx, frame);

        // Отрисовка статус-бара
        self.draw_status_bar(ctx);

        // Основное содержимое
        egui::CentralPanel::default().show(ctx, |ui| {
            // Панель вкладок
            self.draw_tabs(ui);

            ui.add_space(10.0);

            // Сообщения об ошибках и успехе
            self.draw_messages(ui);

            // Содержимое текущей вкладки
            egui::ScrollArea::vertical().show(ui, |ui| {
                match self.current_tab {
                    AppTab::Encrypt => self.draw_encrypt_tab(ui),
                    AppTab::Decrypt => self.draw_decrypt_tab(ui),
                    AppTab::Pack => {
                        ui.heading("Directory Packing");
                        ui.label("Coming soon...");
                    }
                    AppTab::Unpack => {
                        ui.heading("Directory Unpacking");
                        ui.label("Coming soon...");
                    }
                    AppTab::Tools => {
                        ui.heading("Additional Tools");
                        ui.label("Coming soon...");
                    }
                }
            });
        });
    }
} 