//! Crate that implementing simple authorization system.
//!
//! CC Auth uses passwords' hashing with salts, SHA3-256 hash function and Redis-like tokens' storage.
//!
//! Usage:
//!
//! ```rust
//! use bb8_redis::{RedisConnectionManager, bb8::Pool};
//! use cc_auth::{ApiToken, check_token};
//! use cc_utils::prelude::MResult;
//!
//! pub async fn authorized_action(
//!   cacher: &Pool<RedisConnectionManager>,
//!   token: ApiToken,
//! ) -> MResult<()> {
//!   let user_id = check_token(&token, cacher).await?;
//!   Ok(())
//! }
//! ```

use bb8_redis::redis::{AsyncCommands, LposOptions};
use cc_utils::prelude::*;
use chrono::{DateTime, Duration, Utc, serde::ts_seconds};
use passwords::PasswordGenerator;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Standard token length (64 UTF-8 symbols).
const TOKEN_LENGTH: usize = 64;

/// Prefix for tokens' location in Redis-like database.
const TOKEN_PREFIX: &str = "user_tokens";

/// Limit of tokens for one user (3 tokens). If the token limit is exceeded, old tokens will be overwritten.
pub const MAX_TOKENS_PER_USER: isize = 3;

/// Limit of token validation time (each token lives 28 days).
pub const DAYS_VALID: i64 = 28;

/// User identifier type.
///
/// You can use in your own code any ID type you want that convertible into u64.
pub type UserId = u64;

/// Holds user token.
#[derive(Deserialize, Serialize)]
pub struct UserToken {
  pub user_id: UserId,
  token_str: String,
  #[serde(with = "ts_seconds")]
  birth: DateTime<Utc>,
}

impl UserToken {
  pub fn new(id: UserId) -> MResult<Self> { generate_token(id) }
}

/// Token as string (e.g. one that got from `Authorization` header).
pub type ApiToken = String;

/// Gets the salted password's SHA3-256 hash.
pub fn hash_password(user_password: &[u8], user_salt: &[u8]) -> Vec<u8> {
  let mut hasher = Sha3_256::new();
  hasher.update([user_password, user_salt].concat());
  hasher.finalize().to_vec()
}

/// Checks the password is correct.
pub fn hashes_eq(user_password: &[u8], salt_from_db: &[u8], hash_from_db: &[u8]) -> bool {
  hash_password(user_password, salt_from_db).eq(hash_from_db)
}

/// Returns the name of the list in Redis-like DB that stores the users' tokens.
pub fn get_user_tokens_list_name(user_id: UserId) -> String {
  format!("{}:id{}", TOKEN_PREFIX, user_id)
}

/// Authorizes the user by creating a new token for him if the data is correct.
pub async fn log_in(
  user_login: String,
  salt_db: &[u8],
  hash_db: &[u8],
  possible_user_id: UserId,
  cacher: &bb8_redis::bb8::Pool<bb8_redis::RedisConnectionManager>,
) -> MResult<UserToken> {
  if !hashes_eq(user_login.as_bytes(), salt_db, hash_db) { return Err("Hashes are not equal.".into()) } ;
  let utl_name = get_user_tokens_list_name(possible_user_id);
  let mut cacher_conn = cacher.get().await?;
  let user_tokens_list_len: isize = cacher_conn.llen(&utl_name).await?;
  let token = generate_token(possible_user_id)?;
  if user_tokens_list_len >= MAX_TOKENS_PER_USER { cacher_conn.ltrim(&utl_name, 0, MAX_TOKENS_PER_USER - 1).await?; }
  cacher_conn.lpush(&utl_name, &serde_json::to_string(&token)?).await?;
  Ok(token)
}

/// Validates the user by token via Redis-like DB.
pub async fn check_token(
  token: &ApiToken,
  cacher: &bb8_redis::bb8::Pool<bb8_redis::RedisConnectionManager>,
) -> MResult<UserId> {
  let token_data = serde_json::from_str::<UserToken>(&token)?;
  let user_tokens_list = get_user_tokens_list_name(token_data.user_id);
  let mut cacher_conn = cacher.get().await?;
  let idx: Option<i32> = cacher_conn.lpos(&user_tokens_list, &token, LposOptions::default()).await?;
  if idx.is_none() { return Err("There is no such tokens.".into()) }
  let duration: Duration = Utc::now() - token_data.birth;
  if duration.num_days() >= DAYS_VALID {
    cacher_conn.lrem(user_tokens_list, 1, &token).await?;
    return Err("The token is expired.".into())
  }
  Ok(token_data.user_id)
}

/// Removes the valid token from Redis-like DB.
pub async fn check_and_remove_token(
  token: &ApiToken,
  cacher: &bb8_redis::bb8::Pool<bb8_redis::RedisConnectionManager>,
) -> MResult<()> {
  let token_data = serde_json::from_str::<UserToken>(&token)?;
  let user_tokens_list = get_user_tokens_list_name(token_data.user_id);
  let mut cacher_conn = cacher.get().await?;
  let idx: Option<i32> = cacher_conn.lpos(&user_tokens_list, &token, LposOptions::default()).await?;
  if idx.is_none() { return Err("There is no such tokens.".into()) }
  cacher_conn.lrem(user_tokens_list, 1, &token).await?;
  Ok(())
}

/// Creates fixed length password generator.
fn get_password_generator(length: usize) -> PasswordGenerator {
  PasswordGenerator {
    length,
    numbers: true,
    lowercase_letters: true,
    uppercase_letters: true,
    symbols: true,
    strict: true,
    exclude_similar_characters: true,
    spaces: false,
  }
}

/// Generates new token for user.
pub fn generate_token(user_id: UserId) -> MResult<UserToken> {
  Ok(UserToken {
    user_id,
    token_str: get_password_generator(TOKEN_LENGTH).generate_one()?,
    birth: Utc::now(),
  })
}

/// Generates salt for new user.
pub fn generate_salt() -> MResult<String> {
  Ok(get_password_generator(16).generate_one()?)
}