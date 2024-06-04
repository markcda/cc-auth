# cc-auth

[![crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]
[![docs.rs][docs-badge]][docs-url]

[crates-badge]: https://img.shields.io/crates/v/cc-auth.svg
[crates-url]: https://crates.io/crates/cc-auth
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/tokio-rs/tokio/blob/master/LICENSE
[docs-badge]: https://img.shields.io/docsrs/cc-auth
[docs-url]: https://docs.rs/cc-auth

Simple backend authorization system.

## Simple usage example

```rust
use bb8_redis::{RedisConnectionManager, bb8::Pool};
use cc_auth::{ApiToken, check_token};
use cc_utils::prelude::MResult;

pub async fn authorized_action(
  cacher: &Pool<RedisConnectionManager>,
  token: ApiToken,
) -> MResult<()> {
  let user_id = check_token(&token, cacher).await?;
  Ok(())
}
```