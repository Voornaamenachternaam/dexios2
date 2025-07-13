use eframe::egui;
use std::path::PathBuf;

use crate::secure_string::SecureString;

/// Отрисовка защищенного поля ввода пароля
pub fn password_field(ui: &mut egui::Ui, label: &str, password: &mut SecureString) -> egui::Response {
    ui.horizontal(|ui| {
        ui.label(label);
        let response = ui.add(egui::TextEdit::singleline(password.as_mut_string())
            .password(true)
            .hint_text("Enter password"));
        response
    }).inner
}

/// Отрисовка поля выбора файла
pub fn file_picker_field(
    ui: &mut egui::Ui, 
    label: &str, 
    path: &mut Option<PathBuf>, 
    button_text: &str
) -> bool {
    let mut file_selected = false;
    
    ui.horizontal(|ui| {
        ui.label(label);
        
        let display_text = match path {
            Some(p) => p.to_string_lossy().to_string(),
            None => "No file selected".to_string(),
        };
        
        ui.add(egui::TextEdit::singleline(&mut display_text.clone())
            .desired_width(300.0)
            .interactive(false));
        
        if ui.button(button_text).clicked() {
            file_selected = true;
        }
    });
    
    file_selected
}

/// Отрисовка группы чекбоксов в рамке
pub fn checkbox_group<F>(ui: &mut egui::Ui, title: &str, content: F) 
where 
    F: FnOnce(&mut egui::Ui)
{
    ui.group(|ui| {
        ui.label(egui::RichText::new(title).strong());
        ui.separator();
        content(ui);
    });
}

/// Отрисовка прогресс-бара с текстом
pub fn progress_bar_with_text(ui: &mut egui::Ui, progress: f32, text: &str) {
    ui.vertical(|ui| {
        ui.label(text);
        ui.add(egui::ProgressBar::new(progress).show_percentage());
    });
}

/// Отрисовка кнопки с подтверждением для деструктивных операций
pub fn destructive_button(ui: &mut egui::Ui, text: &str, enabled: bool) -> bool {
    ui.add_enabled(enabled, egui::Button::new(egui::RichText::new(text).color(egui::Color32::from_rgb(255, 100, 100))))
        .clicked()
}

/// Отрисовка информационной панели
pub fn info_panel(ui: &mut egui::Ui, title: &str, content: &str) {
    ui.collapsing(title, |ui| {
        ui.label(content);
    });
}

/// Отрисовка панели ошибки
pub fn error_panel(ui: &mut egui::Ui, error: &str) {
    ui.group(|ui| {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("⚠").color(egui::Color32::from_rgb(255, 100, 100)));
            ui.label(egui::RichText::new(error).color(egui::Color32::from_rgb(255, 100, 100)));
        });
    });
}

/// Отрисовка панели успеха
pub fn success_panel(ui: &mut egui::Ui, message: &str) {
    ui.group(|ui| {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("✓").color(egui::Color32::from_rgb(100, 255, 100)));
            ui.label(egui::RichText::new(message).color(egui::Color32::from_rgb(100, 255, 100)));
        });
    });
} 