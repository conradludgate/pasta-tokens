# pasta_tokens

PASETO implementation for Rust.

## Examples

```rust
use pasta_tokens::{
    purpose::public::{
        Public, PublicKey, SecretKey, SignedToken, UnsignedToken, VerifiedToken,
    },
    version::V4,
    paserk::id::KeyId,
    Json,
};

#[derive(serde::Serialize, serde::Deserialize)]
struct Footer {
    /// The ID of the key used to sign the PASETO.
    /// A footer should only contain types that are `SafeForFooter`
    kid: KeyId<V4, Public>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Payload {
    /// The expiration date of the token
    #[serde(with = "time::serde::rfc3339", rename = "exp")]
    expiration: time::OffsetDateTime,
    /// The subject of the token
    #[serde(rename = "sub")]
    user_id: uuid::Uuid,
}

// load your secret key
let secret_key = hex::decode("407796f4bc4b8184e9fe0c54b336822d34823092ad873d87ba14c3efb9db8c1d").unwrap();
let secret_key = SecretKey::from_secret_key(secret_key.try_into().unwrap());

let user_id = uuid::Uuid::new_v4();

// create the token payload and footer.
let token = UnsignedToken::new_v4_public(Payload {
        // expires in 1 hour
        expiration: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        user_id,
    })
    .with_footer(Json(Footer {
        kid: secret_key.public_key().to_id(),
    }))
    // sign with the secret key
    .sign(&secret_key)
    .unwrap()
    .to_string();

// Send off the token to the client
println!("{token}");
// "v4.public.eyJleHAiOiIyMDIzLTEwLTAxVDE0OjQ4OjI2LjM0NjA5MloiLCJzdWIiOiIxOTBhZjFmYS1lZGVlLTRiNGUtOGQxMC05ZmUwZjQ1ZGQ5OTQifXo-Vsr45NroJZ9pLkuN3xcxgFncGF3eject5GdZH7WwTEfCgmo6hD-zNh0txsLvZi1vC601oNCgXq_2cK4XKQw.eyJraWQiOiJrNC5waWQuQUdQQ09CUkI4UHowQ3dNOFFfQnNVUEw0OF8zZjRUbE0yc2Z0R3Y0ejkzVFkifQ"

// load your public keys
let public_key = hex::decode("b7715bd661458d928654d3e832f53ff5c9480542e0e3d4c9b032c768c7ce6023").unwrap();
let public_key = PublicKey::from_public_key(&public_key).unwrap();

// keep a key cache of key IDs to public keys.
// this will let you securely rotate your secret keys
// and still validate multiple public keys safely
let keys = std::collections::HashMap::from([
    (public_key.to_id(), public_key)
]);

// Parse the token from the client
let token: SignedToken<V4, Json<Footer>> = token.parse().expect("should be a valid token format");

// using the key ID, search for the public key
let key = &keys[&token.unverified_footer().0.kid];

// verify the token signature
let token: VerifiedToken<V4, Payload, _> = token.verify(key).expect("token should be signed by us");

// check if the token has expired
assert!(token.message.expiration > time::OffsetDateTime::now_utc());

// proceed to use the payload as you wish!
assert_eq!(token.message.user_id, user_id);
```
