use std::str::FromStr;

use criterion::{
    black_box, criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, Criterion,
};
use pasta_tokens::{
    key::KeyType,
    purpose::{
        local::{EncryptedToken, LocalVersion, SymmetricKey},
        public::{PublicKey, PublicVersion, SecretKey, SignedToken},
        Local, Public, Purpose,
    },
    tokens::TokenBuilder,
    v3, v4,
    version::{Version, V3, V4},
    Json,
};

#[derive(serde::Serialize, serde::Deserialize)]
struct Footer {
    kid: String,
    wpk: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Payload {
    sub: String,
    exp: String,
    aud: String,
}

fn new_token<V: Version, P: Purpose>() -> TokenBuilder<V, P, Payload, Json<Footer>> {
    TokenBuilder::new(Payload {
        aud: "acme.example.com".to_string(),
        exp: "this token expires at some point".to_string(),
        sub: "this tokens is for a user somewhere in the world".to_string(),
    })
    .with_footer(Json(Footer {
        kid: "the key is a very special key".to_string(),
        wpk: "this key is unwrapped :(".to_string(),
    }))
}

pub fn criterion_benchmark(c: &mut Criterion) {
    local::<V3>(c.benchmark_group("v3/paseto/local"));
    local::<V4>(c.benchmark_group("v4/paseto/local"));
    let v3_secret_key = v3::SecretKey::new_os_random();
    let v4_secret_key = v4::SecretKey::new_os_random();
    public(
        v3_secret_key.public_key(),
        v3_secret_key,
        c.benchmark_group("v3/paseto/public"),
    );
    public(
        v4_secret_key.public_key(),
        v4_secret_key,
        c.benchmark_group("v4/paseto/public"),
    );
}

fn local<V: LocalVersion>(mut g: BenchmarkGroup<'_, WallTime>) {
    let key = SymmetricKey::<V>::new_os_random();
    let encrypted_token = new_token::<V, Local>().encrypt(&key).unwrap();
    let encoded_token = encrypted_token.to_string();

    g.bench_function("encrypt", |b| {
        b.iter_batched(
            new_token::<V, Local>,
            |t| t.encrypt(black_box(&key)).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });
    g.bench_function("decrypt", |b| {
        b.iter_batched(
            || new_token::<V, Local>().encrypt(&key).unwrap(),
            |t| t.decrypt::<Payload>(black_box(&key)).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });

    g.bench_function("encode", |b| b.iter(|| encrypted_token.to_string()));
    g.bench_function("decode", |b| {
        b.iter(|| EncryptedToken::<V, Json<Footer>>::from_str(&encoded_token).unwrap())
    });
}

fn public<V: PublicVersion>(
    public_key: PublicKey<V>,
    secret_key: SecretKey<V>,
    mut g: BenchmarkGroup<'_, WallTime>,
) {
    let signed_token = new_token::<V, Public>().sign(&secret_key).unwrap();
    let encoded_token = signed_token.to_string();

    g.bench_function("sign", |b| {
        b.iter_batched(
            new_token::<V, Public>,
            |t| t.sign(black_box(&secret_key)).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });
    g.bench_function("verify", |b| {
        b.iter_batched(
            || new_token::<V, Public>().sign(&secret_key).unwrap(),
            |t| t.verify::<Payload>(black_box(&public_key)).unwrap(),
            criterion::BatchSize::SmallInput,
        )
    });

    g.bench_function("encode", |b| b.iter(|| signed_token.to_string()));
    g.bench_function("decode", |b| {
        b.iter(|| SignedToken::<V, Json<Footer>>::from_str(&encoded_token).unwrap())
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
