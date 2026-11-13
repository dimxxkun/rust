//! Core generator and entropy calculation module.

pub struct PasswordConfig {
    pub length: usize,
    pub include_uppercase: bool,
    pub include_lowercase: bool,
    pub include_digits: bool,
    pub include_symbols: bool,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            length: 16,
            include_uppercase: true,
            include_lowercase: true,
            include_digits: true,
            include_symbols: true,
        }
    }
}

/// Simple pseudorandom generator (LCG) for deterministic or fast standalone use without external crates
pub struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x4d595df4d0f33173 } else { seed },
        }
    }

    pub fn next_u32(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        (self.state >> 32) as u32
    }
}

pub fn generate_password(config: &PasswordConfig, rng: &mut SimpleRng) -> String {
    let mut charset = Vec::new();
    if config.include_uppercase {
        charset.extend(b'A'..=b'Z');
    }
    if config.include_lowercase {
        charset.extend(b'a'..=b'z');
    }
    if config.include_digits {
        charset.extend(b'0'..=b'9');
    }
    if config.include_symbols {
        charset.extend(b"!@#$%^&*()-_=+[]{}<>?".iter().copied());
    }

    if charset.is_empty() {
        return String::new();
    }

    let mut result = Vec::with_capacity(config.length);
    for _ in 0..config.length {
        let idx = (rng.next_u32() as usize) % charset.len();
        result.push(charset[idx]);
    }

    String::from_utf8(result).unwrap_or_default()
}

/// Calculates password entropy in bits: E = L * log2(R)
pub fn calculate_entropy(length: usize, charset_size: usize) -> f64 {
    if length == 0 || charset_size == 0 {
        return 0.0;
    }
    (length as f64) * (charset_size as f64).log2()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_length() {
        let config = PasswordConfig {
            length: 12,
            ..Default::default()
        };
        let mut rng = SimpleRng::new(12345);
        let pwd = generate_password(&config, &mut rng);
        assert_eq!(pwd.len(), 12);
    }

    #[test]
    fn test_entropy() {
        let entropy = calculate_entropy(10, 10); // 10 digits
        assert!((entropy - 33.219).abs() < 0.01);
    }
}

