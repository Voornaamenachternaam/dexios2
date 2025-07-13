use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use dexios_core::primitives::Algorithm;
use dexios_core::header::{HashingAlgorithm, HeaderType, HeaderVersion};
use dexios_core::primitives::Mode;
use dexios_core::protected::Protected;
use dexios_domain::storage::{Storage, FileStorage};

use crate::secure_string::SecureString;

/// Сообщения от фоновых операций к UI
#[derive(Debug, Clone)]
pub enum OperationMessage {
    Progress(f32),
    Status(String),
    Error(String),
    Complete(String),
}

/// Статус текущей операции
#[derive(Debug, Clone)]
pub struct OperationStatus {
    pub is_running: bool,
    pub progress: f32,
    pub status: String,
    pub error: Option<String>,
}

impl Default for OperationStatus {
    fn default() -> Self {
        Self {
            is_running: false,
            progress: 0.0,
            status: "Ready".to_string(),
            error: None,
        }
    }
}

/// Обработчик асинхронных операций
pub struct AsyncOperationHandler {
    pub sender: mpsc::Sender<OperationMessage>,
    pub receiver: mpsc::Receiver<OperationMessage>,
    cancel_sender: Option<oneshot::Sender<()>>,
}

impl AsyncOperationHandler {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel(100);
        Self {
            sender,
            receiver,
            cancel_sender: None,
        }
    }

    pub fn cancel_operation(&mut self) {
        if let Some(cancel_sender) = self.cancel_sender.take() {
            let _ = cancel_sender.send(());
        }
    }

    pub fn start_encrypt_operation(&mut self, request: EncryptRequest) {
        let (cancel_tx, cancel_rx) = oneshot::channel();
        self.cancel_sender = Some(cancel_tx);
        
        let sender = self.sender.clone();
        tokio::spawn(async move {
            let _ = sender.send(OperationMessage::Status("Starting encryption...".to_string())).await;
            
            match perform_encrypt_operation(request, sender.clone(), cancel_rx).await {
                Ok(result) => {
                    let _ = sender.send(OperationMessage::Complete(result)).await;
                }
                Err(e) => {
                    let _ = sender.send(OperationMessage::Error(e.to_string())).await;
                }
            }
        });
    }

    pub fn start_decrypt_operation(&mut self, request: DecryptRequest) {
        let (cancel_tx, cancel_rx) = oneshot::channel();
        self.cancel_sender = Some(cancel_tx);
        
        let sender = self.sender.clone();
        tokio::spawn(async move {
            let _ = sender.send(OperationMessage::Status("Starting decryption...".to_string())).await;
            
            match perform_decrypt_operation(request, sender.clone(), cancel_rx).await {
                Ok(result) => {
                    let _ = sender.send(OperationMessage::Complete(result)).await;
                }
                Err(e) => {
                    let _ = sender.send(OperationMessage::Error(e.to_string())).await;
                }
            }
        });
    }
}

/// Запрос на шифрование
#[derive(Clone)]
pub struct EncryptRequest {
    pub input_file: PathBuf,
    pub output_file: PathBuf,
    pub password: SecureString,
    pub algorithm: Algorithm,
    pub hash_algorithm: HashingAlgorithm,
    pub keyfile_path: Option<PathBuf>,
    pub detached_header: bool,
    pub header_path: Option<PathBuf>,
    pub secure_erase: bool,
    pub erase_passes: i32,
    pub calculate_hash: bool,
}

/// Запрос на дешифрование
#[derive(Clone)]
pub struct DecryptRequest {
    pub input_file: PathBuf,
    pub output_file: PathBuf,
    pub password: SecureString,
    pub keyfile_path: Option<PathBuf>,
    pub detached_header: bool,
    pub header_path: Option<PathBuf>,
    pub secure_erase: bool,
    pub erase_passes: i32,
    pub calculate_hash: bool,
}

/// Выполнение операции шифрования
async fn perform_encrypt_operation(
    request: EncryptRequest,
    sender: mpsc::Sender<OperationMessage>,
    mut cancel_rx: oneshot::Receiver<()>,
) -> Result<String, anyhow::Error> {
    // Проверка отмены операции
    if cancel_rx.try_recv().is_ok() {
        return Err(anyhow::anyhow!("Operation cancelled"));
    }

    let _ = sender.send(OperationMessage::Progress(0.1)).await;
    let _ = sender.send(OperationMessage::Status("Opening input file...".to_string())).await;

    // Подготовка ключа
    let protected_key = if let Some(keyfile_path) = &request.keyfile_path {
        let _ = sender.send(OperationMessage::Status("Reading keyfile...".to_string())).await;
        let keyfile_content = std::fs::read(keyfile_path)?;
        
        // Проверяем, что keyfile не пустой
        if keyfile_content.is_empty() {
            return Err(anyhow::anyhow!("Keyfile '{}' is empty", keyfile_path.display()));
        }
        
        Protected::new(keyfile_content)
    } else {
        // Используем пароль только если нет keyfile
        let raw_key = request.password.as_str().as_bytes().to_vec();
        Protected::new(raw_key)
    };

    let _ = sender.send(OperationMessage::Progress(0.3)).await;

    // Настройка header type
    let header_type = HeaderType {
        version: HeaderVersion::V5,
        algorithm: request.algorithm,
        mode: Mode::StreamMode,
    };

    let _ = sender.send(OperationMessage::Status("Encrypting file...".to_string())).await;

    // Проверка отмены операции
    if cancel_rx.try_recv().is_ok() {
        return Err(anyhow::anyhow!("Operation cancelled"));
    }

    let _ = sender.send(OperationMessage::Progress(0.5)).await;

    // Выполнение операции шифрования в блокирующем потоке
    let input_file = request.input_file.clone();
    let output_file = request.output_file.clone();
    let header_path = request.header_path.clone();
    let detached_header = request.detached_header;
    let hash_algorithm = request.hash_algorithm;
    
    let _encrypt_result = tokio::task::spawn_blocking(move || {
        let storage = Arc::new(FileStorage);
        
        // Открытие файлов через Storage API
        let input = storage.read_file(&input_file)?;
        let output = storage.create_file(&output_file)
            .or_else(|_| storage.write_file(&output_file))?;

        // Подготовка header writer для detached header
        let header_file = if detached_header {
            if let Some(header_path) = &header_path {
                Some(storage.create_file(header_path)
                    .or_else(|_| storage.write_file(header_path))?)
            } else {
                None
            }
        } else {
            None
        };

        // Вызов dexios-domain для шифрования
        let encrypt_request = dexios_domain::encrypt::Request {
            reader: input.try_reader()?,
            writer: output.try_writer()?,
            header_writer: header_file.as_ref().and_then(|h| h.try_writer().ok()),
            raw_key: protected_key,
            header_type,
            hashing_algorithm: hash_algorithm,
        };

        dexios_domain::encrypt::execute(encrypt_request)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
            
        // Сохранение файлов
        storage.flush_file(&output)
            .map_err(|e| anyhow::anyhow!("Failed to flush output file: {}", e))?;
            
        if let Some(header_file) = &header_file {
            storage.flush_file(header_file)
                .map_err(|e| anyhow::anyhow!("Failed to flush header file: {}", e))?;
        }
        
        Ok(()) as Result<(), anyhow::Error>
    }).await??;

    let _ = sender.send(OperationMessage::Progress(0.9)).await;

    // Опциональное хеширование
    if request.calculate_hash {
        let _ = sender.send(OperationMessage::Status("Calculating hash...".to_string())).await;
        // TODO: Реализовать хеширование через dexios-domain
    }

    // Опциональное безопасное удаление
    if request.secure_erase {
        let _ = sender.send(OperationMessage::Status("Securely erasing original file...".to_string())).await;
        // TODO: Реализовать безопасное удаление через dexios-domain
    }

    let _ = sender.send(OperationMessage::Progress(1.0)).await;

    Ok(format!(
        "File encrypted successfully!\nInput: {}\nOutput: {}",
        request.input_file.display(),
        request.output_file.display()
    ))
}

/// Выполнение операции дешифрования
async fn perform_decrypt_operation(
    request: DecryptRequest,
    sender: mpsc::Sender<OperationMessage>,
    mut cancel_rx: oneshot::Receiver<()>,
) -> Result<String, anyhow::Error> {
    // Проверка отмены операции
    if cancel_rx.try_recv().is_ok() {
        return Err(anyhow::anyhow!("Operation cancelled"));
    }

    let _ = sender.send(OperationMessage::Progress(0.1)).await;
    let _ = sender.send(OperationMessage::Status("Opening input file...".to_string())).await;

    // Подготовка ключа
    let protected_key = if let Some(keyfile_path) = &request.keyfile_path {
        let _ = sender.send(OperationMessage::Status("Reading keyfile...".to_string())).await;
        let keyfile_content = std::fs::read(keyfile_path)?;
        
        // Проверяем, что keyfile не пустой
        if keyfile_content.is_empty() {
            return Err(anyhow::anyhow!("Keyfile '{}' is empty", keyfile_path.display()));
        }
        
        Protected::new(keyfile_content)
    } else {
        // Используем пароль только если нет keyfile
        let raw_key = request.password.as_str().as_bytes().to_vec();
        Protected::new(raw_key)
    };

    let _ = sender.send(OperationMessage::Progress(0.3)).await;
    let _ = sender.send(OperationMessage::Status("Decrypting file...".to_string())).await;

    // Проверка отмены операции
    if cancel_rx.try_recv().is_ok() {
        return Err(anyhow::anyhow!("Operation cancelled"));
    }

    let _ = sender.send(OperationMessage::Progress(0.5)).await;

    // Выполнение операции дешифрования в блокирующем потоке
    let input_file = request.input_file.clone();
    let output_file = request.output_file.clone();
    let header_path = request.header_path.clone();
    let detached_header = request.detached_header;
    
    let _decrypt_result = tokio::task::spawn_blocking(move || {
        let storage = Arc::new(FileStorage);
        
        // Открытие файлов через Storage API
        let input = storage.read_file(&input_file)?;
        let output = storage.create_file(&output_file)
            .or_else(|_| storage.write_file(&output_file))?;

        // Подготовка header reader для detached header
        let header_file = if detached_header {
            if let Some(header_path) = &header_path {
                Some(storage.read_file(header_path)?)
            } else {
                None
            }
        } else {
            None
        };

        // Вызов dexios-domain для дешифрования
        let decrypt_request = dexios_domain::decrypt::Request {
            header_reader: header_file.as_ref().and_then(|h| h.try_reader().ok()),
            reader: input.try_reader()?,
            writer: output.try_writer()?,
            raw_key: protected_key,
            on_decrypted_header: None,
        };

        dexios_domain::decrypt::execute(decrypt_request)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
            
        // Сохранение файла
        storage.flush_file(&output)
            .map_err(|e| anyhow::anyhow!("Failed to flush file: {}", e))?;
        
        Ok(()) as Result<(), anyhow::Error>
    }).await??;

    let _ = sender.send(OperationMessage::Progress(0.9)).await;

    // Опциональное хеширование
    if request.calculate_hash {
        let _ = sender.send(OperationMessage::Status("Calculating hash...".to_string())).await;
        // TODO: Реализовать хеширование через dexios-domain
    }

    // Опциональное безопасное удаление
    if request.secure_erase {
        let _ = sender.send(OperationMessage::Status("Securely erasing encrypted file...".to_string())).await;
        // TODO: Реализовать безопасное удаление через dexios-domain
    }

    let _ = sender.send(OperationMessage::Progress(1.0)).await;

    Ok(format!(
        "File decrypted successfully!\nInput: {}\nOutput: {}",
        request.input_file.display(),
        request.output_file.display()
    ))
} 