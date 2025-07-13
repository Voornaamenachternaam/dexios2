use zeroize::Zeroize;

/// Безопасная строка для хранения паролей
/// Автоматически очищается из памяти при удалении
#[derive(Clone, Debug)]
pub struct SecureString {
    inner: String,
}

impl SecureString {
    pub fn new() -> Self {
        Self {
            inner: String::new(),
        }
    }

    pub fn from_string(s: String) -> Self {
        Self { inner: s }
    }

    pub fn as_str(&self) -> &str {
        &self.inner
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn clear(&mut self) {
        self.inner.zeroize();
    }

    pub fn push(&mut self, c: char) {
        self.inner.push(c);
    }

    pub fn pop(&mut self) -> Option<char> {
        self.inner.pop()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn as_mut_string(&mut self) -> &mut String {
        &mut self.inner
    }
}

impl Default for SecureString {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for SecureString {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        self.clear();
    }
}

impl From<&str> for SecureString {
    fn from(s: &str) -> Self {
        Self {
            inner: s.to_string(),
        }
    }
}

impl From<String> for SecureString {
    fn from(s: String) -> Self {
        Self { inner: s }
    }
} 