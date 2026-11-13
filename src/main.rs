use rust_starter::{calculate_entropy, generate_password, PasswordConfig, SimpleRng};

fn main() {
    println!("=========================================");
    println!("     Rust - Password & Entropy CLI       ");
    println!("=========================================");

    let mut rng = SimpleRng::new(987654321);

    let presets = vec![
        ("Standard (16 chars)", PasswordConfig { length: 16, ..Default::default() }, 93),
        ("PIN Code (6 digits)", PasswordConfig { length: 6, include_uppercase: false, include_lowercase: false, include_digits: true, include_symbols: false }, 10),
        ("High Security (32 chars)", PasswordConfig { length: 32, ..Default::default() }, 93),
    ];

    for (name, config, charset_size) in presets {
        let password = generate_password(&config, &mut rng);
        let entropy = calculate_entropy(config.length, charset_size);
        println!("\nPreset: {}", name);
        println!("  • Result:  {}", password);
        println!("  • Length:  {} chars", config.length);
        println!("  • Entropy: {:.2} bits", entropy);
    }

    println!("\nAll tasks completed successfully!");
}
