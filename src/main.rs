use std::{
    io::{self, Write},
    time::Duration,
};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng as ArgonOsRng},
};
use clipboard::{ClipboardContext, ClipboardProvider};
use color_eyre::{Result, eyre::eyre};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::{Rng, distr::Alphanumeric};
use rpassword::prompt_password;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::Sha256;
use zeroize::Zeroizing;

const DB_NAME: &str = "passwords.db";
const KEY_LENGTH: usize = 32; // 256 бит для AES-256
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12; // Для AES-GCM
const PBKDF2_ITERATIONS: u32 = 100_000;

struct PasswordEntry {
    id: i64,
    service: String,
    login: String,
    password_ciphertext: Vec<u8>,
    salt: Vec<u8>,
    nonce: Vec<u8>,
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let conn = init_db()?;

    // Проверка/установка мастер-пароля
    let master_password = Zeroizing::new(if let Some(mph) = get_master_pass(&conn)? {
        let input = Zeroizing::new(prompt_password("Введите 🗝️  мастер-пароль: ")?);
        if Argon2::default()
            .verify_password(input.as_bytes(), &PasswordHash::new(&mph)?)
            .is_err()
        {
            return Err(eyre!("❌ Неверный мастер-пароль"));
        }
        input
    } else {
        let new_master = Zeroizing::new(prompt_password("Создайте  🗝️  мастер-пароль: ")?);
        let confirm = Zeroizing::new(prompt_password("Подтвердите  🗝️  мастер-пароль: ")?);

        if new_master != confirm {
            return Err(eyre!("❌ Пароли не совпадают"));
        }

        let salt = SaltString::generate(&mut ArgonOsRng);
        let mph = Argon2::default()
            .hash_password(new_master.as_bytes(), &salt)?
            .to_string();
        set_master_pass(&conn, mph)?;
        new_master
    });

    println!("Добро пожаловать в менеджер паролей! 🧑‍💼");
    loop {
        println!("\n📱 Меню:");
        println!("1. 🆕 Добавить пароль");
        println!("2. 🎁 Получить пароль");
        println!("3. ☠️  Удалить пароль");
        println!("4. 🔐 Сгенерировать пароль");
        println!("5. ⛔ Выход");

        print!("Выберите действие: ");
        io::stdout().flush()?;

        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;

        match choice.trim() {
            "1" => add_password(&conn, &master_password)?,
            "2" => get_password(&conn, &master_password)?,
            "3" => delete_password(&conn)?,
            "4" => generate_password()?,
            "5" => break,
            _ => println!("Неверный выбор"),
        }
    }
    Ok(())
}

fn init_db() -> Result<Connection> {
    let conn = Connection::open(DB_NAME)?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            service TEXT NOT NULL UNIQUE,
            login TEXT NOT NULL,
            password_ciphertext BLOB NOT NULL,
            salt BLOB NOT NULL,
            nonce BLOB NOT NULL
        )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS master_password (
            password_hash TEXT NOT NULL PRIMARY KEY
        )",
        [],
    )?;
    Ok(conn)
}

fn get_master_pass(conn: &Connection) -> Result<Option<String>> {
    conn.query_row(
        "SELECT password_hash FROM master_password LIMIT 1",
        [],
        |row| row.get(0),
    )
    .optional()
    .map_err(Into::into)
}

fn set_master_pass(conn: &Connection, password_hash: String) -> Result<()> {
    conn.execute(
        "INSERT INTO master_password (password_hash) VALUES(?1)",
        params![password_hash],
    )?;
    Ok(())
}

fn derive_key(master_password: &str, salt: &[u8]) -> Result<[u8; KEY_LENGTH]> {
    let mut key = [0u8; KEY_LENGTH];
    pbkdf2::<Hmac<Sha256>>(
        master_password.as_bytes(),
        salt,
        PBKDF2_ITERATIONS,
        &mut key,
    )?;
    Ok(key)
}

fn encrypt_password(password: &str, master_password: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let salt: Vec<u8> = rand::rng()
        .sample_iter(rand::distr::StandardUniform)
        .take(SALT_LENGTH)
        .collect();

    let key = derive_key(master_password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)?;

    let nonce: Vec<u8> = rand::rng()
        .sample_iter(rand::distr::StandardUniform)
        .take(NONCE_LENGTH)
        .collect();
    let nonce = Nonce::from_slice(&nonce);

    let ciphertext = cipher
        .encrypt(nonce, password.as_bytes())
        .map_err(|e| eyre!(e.to_string()))?;

    Ok((ciphertext, salt, nonce.to_vec()))
}

fn decrypt_password(
    ciphertext: &[u8],
    master_password: &str,
    salt: &[u8],
    nonce: &[u8],
) -> Result<String> {
    let key = derive_key(master_password, salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let nonce = Nonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| eyre!(e.to_string()))?;
    String::from_utf8(plaintext).map_err(|e| eyre!("Ошибка UTF-8: {e}"))
}

fn add_password(conn: &Connection, master_password: &str) -> Result<()> {
    print!("Сервис: ");
    io::stdout().flush()?;
    let mut service = String::new();
    io::stdin().read_line(&mut service)?;
    let service = service.trim();

    print!("Логин: ");
    io::stdout().flush()?;
    let mut login = String::new();
    io::stdin().read_line(&mut login)?;
    let login = login.trim();

    let password = Zeroizing::new(prompt_password(
        "Пароль (введите 'gen' для генерации пароля): ",
    )?);

    let password = if password.as_str() == "gen" {
        Zeroizing::new(generate_password_internal()?)
    } else {
        password
    };

    let (ciphertext, salt, nonce) = encrypt_password(&password, master_password)?;

    conn.execute(
        "INSERT INTO passwords (service, login, password_ciphertext, salt, nonce) VALUES(?1, ?2, ?3, ?4, ?5)",
        params![service, login, ciphertext, salt, nonce],
    )?;

    println!("Пароль успешно добавлен для сервиса {service}");
    Ok(())
}

fn get_all_passwords(conn: &Connection) -> Result<Vec<PasswordEntry>> {
    let mut stmt =
        conn.prepare("SELECT id, service, login, password_ciphertext, salt, nonce FROM passwords")?;
    let rows = stmt.query_map([], |row| {
        Ok(PasswordEntry {
            id: row.get(0)?,
            service: row.get(1)?,
            login: row.get(2)?,
            password_ciphertext: row.get(3)?,
            salt: row.get(4)?,
            nonce: row.get(5)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

fn get_password(conn: &Connection, master_password: &str) -> Result<()> {
    let passwords = get_all_passwords(conn)?;

    if passwords.is_empty() {
        println!("Нет сохраненных паролей");
        return Ok(());
    }

    println!("Список сервисов:");
    for pwd in &passwords {
        println!(
            "ID: {id} ✨ Сервис: {service}",
            id = pwd.id,
            service = pwd.service
        );
    }

    print!("Введите ID сервиса: ");
    io::stdout().flush()?;
    let mut id = String::new();
    io::stdin().read_line(&mut id)?;
    let id: i64 = id.trim().parse()?;

    if let Some(pwd) = passwords.into_iter().find(|p| p.id == id) {
        let decrypted = decrypt_password(
            &pwd.password_ciphertext,
            master_password,
            &pwd.salt,
            &pwd.nonce,
        )?;

        println!("\nДанные для сервиса {service}:", service = pwd.service);
        println!("Логин: {login}", login = pwd.login);
        // println!("Пароль: {decrypted}");
        println!("Пароль: ищите в буфере обмена в течении 30 секунд...");

        if let Ok(mut ctx) = ClipboardContext::new() {
            ctx.set_contents(decrypted)
                .map_err(|e| eyre!(e.to_string()))?;
            println!("Пароль скопирован в буфер обмена");

            // Очистка буфера через 30 секунд
            std::thread::spawn(|| {
                std::thread::sleep(Duration::from_secs(30));
                if let Ok(mut ctx) = ClipboardContext::new() {
                    ctx.set_contents("".to_string()).ok();
                }
            });
        }
    } else {
        println!("Сервис с ID {id} не найден");
    }

    Ok(())
}

fn delete_password(conn: &Connection) -> Result<()> {
    let passwords = get_all_passwords(conn)?;

    if passwords.is_empty() {
        println!("Нет сохраненных паролей");
        return Ok(());
    }

    println!("Список сервисов:");
    for pwd in &passwords {
        println!(
            "ID: {id} ✨ Сервис: {service}",
            id = pwd.id,
            service = pwd.service
        );
    }

    print!("Введите ID сервиса для удаления: ");
    io::stdout().flush()?;
    let mut id = String::new();
    io::stdin().read_line(&mut id)?;
    let id: i64 = id.trim().parse()?;

    conn.execute("DELETE FROM passwords WHERE id = ?1", params![id])?;
    println!("Пароль успешно удален");
    Ok(())
}

fn generate_password() -> Result<()> {
    let password = generate_password_internal()?;
    // println!("Сгенерированный пароль: {password}");
    println!("Сгенерированный пароль: ищите в буфере обмена в течении 30 секунд...");

    if let Ok(mut ctx) = ClipboardContext::new() {
        ctx.set_contents(password.clone())
            .map_err(|e| eyre!(e.to_string()))?;
        println!("Пароль скопирован в буфер обмена");

        // Очистка буфера через 30 секунд
        std::thread::spawn(|| {
            std::thread::sleep(Duration::from_secs(30));
            if let Ok(mut ctx) = ClipboardContext::new() {
                ctx.set_contents("".to_string()).ok();
            }
        });
    }
    Ok(())
}

fn generate_password_internal() -> Result<String> {
    let mut rng = rand::rng();
    let length = rng.random_range(16..24);
    let password: String = (0..length)
        .map(|_| {
            let choice = rng.random_range(0..3);
            match choice {
                0 => rng.sample(Alphanumeric) as char,
                1 => (rng.random_range(33_u8..47_u8)) as char, // Спецсимволы
                _ => (rng.random_range(48_u8..57_u8)) as char, // Цифры
            }
        })
        .collect();
    Ok(password)
}
