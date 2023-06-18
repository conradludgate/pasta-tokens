# rusty_paserk

An extension of [`rusty_paseto`](https://github.com/rrrodzilla/rusty_paseto) adding the [Platform Agnostic Serializable Keys](https://github.com/paseto-standard/paserk) specifications on top.

## Examples

### Local Wrapping

```rust
use rusty_paserk::wrap::{Pie, LocalWrapperExt};
use rusty_paseto::core::{PasetoSymmetricKey, V4, Local, Key};

let wrapping_key = PasetoSymmetricKey::<V4, Local>::from(Key::try_new_random().unwrap());

let local_key = PasetoSymmetricKey::from(Key::try_new_random().unwrap());
let nonce = Key::try_new_random().unwrap();
let wrapped_local = Pie::wrap_local(&local_key, &wrapping_key, &nonce);
// => "k4.local-wrap.pie.RcAvOxHI0H-0uMsIl6KGcplH_tDlOhW1omFwXltZCiynHeRNH0hmn28AkN516h3WHuAReH3CvQ2SZ6mevnTquPETSd3XnlcbRWACT5GLWcus3BsD4IFWm9wFZgNF7C_E"

let mut wrapped_local = wrapped_local.into_bytes();
let local_key2 = Pie::unwrap_local(&mut wrapped_local, &wrapping_key).unwrap();
assert_eq!(local_key.as_ref(), local_key2.as_ref());
```

### Secret Wrapping

```rust
use rusty_paserk::wrap::{Pie, SecretWrapperExt};
use rusty_paseto::core::{PasetoSymmetricKey, PasetoAsymmetricPrivateKey, V4, Key};

let wrapping_key = PasetoSymmetricKey::from(Key::try_new_random().unwrap());

let secret_key = Key::try_new_random().unwrap();
let secret_key = PasetoAsymmetricPrivateKey::from(&secret_key);
let nonce = Key::try_new_random().unwrap();
let wrapped_secret = Pie::wrap_secret(&secret_key, &wrapping_key, &nonce);
// => "k4.secret-wrap.pie.cTTnZwzBA3AKBugQCzmctv5R9CjyPOlelG9SLZrhupDwk6vYx-3UQFCZ7x4d57KU4K4U1qJeFP6ELzkMJ0s8qHt0hsQkW14Ni6TJ89MRzEqglUgI6hJD-EF2E9kIFO5YuC5MHwXN7Wi_vG1S3L-OoTjZgT_ZJ__8T7SJhvYLodo"

let mut wrapped_secret = wrapped_secret.into_bytes();
let secret_key2 = Pie::unwrap_secret(&mut wrapped_secret, &wrapping_key).unwrap();
assert_eq!(secret_key.as_ref(), secret_key2.as_ref());
```

### Local IDs

```rust
use rusty_paserk::id::EncodeId;
use rusty_paseto::core::{PasetoSymmetricKey, V4, Local, Key};

let local_key = PasetoSymmetricKey::<V4, Local>::from(Key::try_new_random().unwrap());
let kid = local_key.encode_id();
// => "k4.lid.XxPub51WIAEmbVTmrs-lFoFodxTSKk8RuYEJk3gl-DYB"
```

### Secret IDs

```rust
use rusty_paserk::id::EncodeId;
use rusty_paseto::core::{PasetoAsymmetricPrivateKey, V4, Public, Key};

let secret_key = Key::try_new_random().unwrap();
let secret_key = PasetoAsymmetricPrivateKey::<V4, Public>::from(&secret_key);
let kid = secret_key.encode_id();
// => "k4.sid.p26RNihDPsk2QbglGMTmwMMqLYyeLY25UOQZXQDXwn61"
```

### Public IDs

```rust
use rusty_paserk::id::EncodeId;
use rusty_paseto::core::{PasetoAsymmetricPublicKey, V4, Public, Key};

let public_key = Key::try_new_random().unwrap();
let public_key = PasetoAsymmetricPublicKey::<V4, Public>::from(&public_key);
let kid = public_key.encode_id();
// => "k4.pid.yMgldRRLHBLkhmcp8NG8yZrtyldbYoAjQWPv_Ma1rzRu"
```
