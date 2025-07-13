use eframe::egui;

mod app;
mod operations;
mod secure_string;
mod ui;

use app::DexiosApp;

fn main() -> Result<(), eframe::Error> {
    // Инициализация логирования
    env_logger::init();

    // Создаем токио рантайм для асинхронных операций
    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
    
    // Входим в контекст рантайма для всего приложения
    let _enter = rt.enter();
    
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 700.0])
            .with_min_inner_size([800.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Dexios - Secure File Encryption",
        options,
        Box::new(|cc| {
            // Настройка визуального стиля
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            
            Ok(Box::new(DexiosApp::new(cc)))
        }),
    )
}
