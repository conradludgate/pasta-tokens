//! PASETO Claims and validators

use std::marker::PhantomData;

use serde::{
    de::{DeserializeSeed, MapAccess, Visitor},
    Deserialize, Deserializer,
};

pub trait Validator {
    fn validate(&self, claim: &str, value: &str);
}

/// PASETO Claims deserializer
///
/// forwards deserialization to the inner, but also extracts out relevant registered claims
struct ClaimsDe<D>(D);

impl<'de, D> Deserializer<'de> for ClaimsDe<D>
where
    D: Deserializer<'de>,
{
    type Error = D::Error;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0.deserialize_any(PasetoClaimVisitor(visitor))
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0.deserialize_bool(PasetoClaimVisitor(visitor))
    }

    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0.deserialize_i8(PasetoClaimVisitor(visitor))
    }

    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0.deserialize_i16(PasetoClaimVisitor(visitor))
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0.deserialize_i32(PasetoClaimVisitor(visitor))
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0.deserialize_i64(PasetoClaimVisitor(visitor))
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0.deserialize_u8(PasetoClaimVisitor(visitor))
    }

    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0.deserialize_u16(PasetoClaimVisitor(visitor))
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0.deserialize_u32(PasetoClaimVisitor(visitor))
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0.deserialize_u64(PasetoClaimVisitor(visitor))
    }

    fn deserialize_f32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0.deserialize_f32(PasetoClaimVisitor(visitor))
    }

    fn deserialize_f64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0.deserialize_f64(PasetoClaimVisitor(visitor))
    }

    fn deserialize_char<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0.deserialize_char(PasetoClaimVisitor(visitor))
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        dbg!("deserialize_str");
        self.0.deserialize_str(PasetoClaimVisitor(visitor))
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        dbg!("deserialize_string");
        self.0.deserialize_string(PasetoClaimVisitor(visitor))
    }

    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0.deserialize_bytes(PasetoClaimVisitor(visitor))
    }

    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0.deserialize_byte_buf(PasetoClaimVisitor(visitor))
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0.deserialize_option(PasetoClaimVisitor(visitor))
    }

    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0.deserialize_unit(PasetoClaimVisitor(visitor))
    }

    fn deserialize_unit_struct<V>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0
            .deserialize_unit_struct(name, PasetoClaimVisitor(visitor))
    }

    fn deserialize_newtype_struct<V>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0
            .deserialize_newtype_struct(name, PasetoClaimVisitor(visitor))
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0.deserialize_seq(PasetoClaimVisitor(visitor))
    }

    fn deserialize_tuple<V>(self, len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0.deserialize_tuple(len, PasetoClaimVisitor(visitor))
    }

    fn deserialize_tuple_struct<V>(
        self,
        name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0
            .deserialize_tuple_struct(name, len, PasetoClaimVisitor(visitor))
    }

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0.deserialize_map(PasetoClaimVisitor(visitor))
    }

    fn deserialize_struct<V>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0
            .deserialize_struct(name, fields, PasetoClaimVisitor(visitor))
    }

    fn deserialize_enum<V>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0
            .deserialize_enum(name, variants, PasetoClaimVisitor(visitor))
    }

    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0.deserialize_identifier(PasetoClaimVisitor(visitor))
    }

    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0.deserialize_ignored_any(PasetoClaimVisitor(visitor))
    }
}

impl<'de, Ds> DeserializeSeed<'de> for ClaimsDe<Ds>
where
    Ds: DeserializeSeed<'de>,
{
    type Value = Ds::Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        self.0.deserialize(ClaimsDe(deserializer))
    }
}

impl<'de, D> Deserialize<'de> for ClaimsDe<D>
where
    D: Deserialize<'de>,
{
    fn deserialize<De>(deserializer: De) -> Result<Self, De::Error>
    where
        De: Deserializer<'de>,
    {
        D::deserialize(ClaimsDe(deserializer)).map(Self)
    }
}

impl<'de, D> MapAccess<'de> for ClaimsDe<D>
where
    D: MapAccess<'de>,
{
    type Error = D::Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
    where
        K: serde::de::DeserializeSeed<'de>,
    {
        dbg!("next_key_seed");
        self.0.next_key_seed(ClaimsDe(seed))
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::DeserializeSeed<'de>,
    {
        dbg!("next_value_seed");
        self.0.next_value_seed(ClaimsDe(seed))
    }

    fn next_entry_seed<K, V>(
        &mut self,
        kseed: K,
        vseed: V,
    ) -> Result<Option<(K::Value, V::Value)>, Self::Error>
    where
        K: serde::de::DeserializeSeed<'de>,
        V: serde::de::DeserializeSeed<'de>,
    {
        dbg!("next_entry_seed");
        self.0.next_entry_seed(ClaimsDe(kseed), ClaimsDe(vseed))
    }

    fn next_key<K>(&mut self) -> Result<Option<K>, Self::Error>
    where
        K: Deserialize<'de>,
    {
        dbg!("next_key");
        self.0.next_key().map(|x| x.map(|ClaimsDe(x)| x))
    }

    fn next_value<V>(&mut self) -> Result<V, Self::Error>
    where
        V: Deserialize<'de>,
    {
        dbg!("next_value");
        self.0.next_value().map(|ClaimsDe(x)| x)
    }

    fn next_entry<K, V>(&mut self) -> Result<Option<(K, V)>, Self::Error>
    where
        K: Deserialize<'de>,
        V: Deserialize<'de>,
    {
        dbg!("next_entry");
        self.0
            .next_entry()
            .map(|x| x.map(|(ClaimsDe(k), ClaimsDe(v))| (k, v)))
    }

    fn size_hint(&self) -> Option<usize> {
        self.0.size_hint()
    }
}

struct PasetoClaimVisitor<V>(V);

impl<'de, V> Visitor<'de> for PasetoClaimVisitor<V>
where
    V: Visitor<'de>,
{
    type Value = V::Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.0.expecting(formatter)
    }

    fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.0.visit_bool(v)
    }

    fn visit_i8<E>(self, v: i8) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.0.visit_i8(v)
    }

    fn visit_i16<E>(self, v: i16) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.0.visit_i16(v)
    }

    fn visit_i32<E>(self, v: i32) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.0.visit_i32(v)
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.0.visit_i64(v)
    }

    fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.0.visit_u8(v)
    }

    fn visit_u16<E>(self, v: u16) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.0.visit_u16(v)
    }

    fn visit_u32<E>(self, v: u32) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.0.visit_u32(v)
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.0.visit_u64(v)
    }

    fn visit_f32<E>(self, v: f32) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.0.visit_f32(v)
    }

    fn visit_f64<E>(self, v: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.0.visit_f64(v)
    }

    fn visit_char<E>(self, v: char) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.0.visit_char(v)
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        println!("visit_str {v:?}");
        self.0.visit_str(v)
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        println!("visit_borrowed_str {v:?}");
        self.0.visit_borrowed_str(v)
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        println!("visit_string {v:?}");
        self.0.visit_string(v)
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.0.visit_bytes(v)
    }

    fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.0.visit_borrowed_bytes(v)
    }

    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.0.visit_byte_buf(v)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.0.visit_none()
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        self.0.visit_some(deserializer)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.0.visit_unit()
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        self.0.visit_newtype_struct(deserializer)
    }

    fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        self.0.visit_seq(seq)
    }

    fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        dbg!("visit_map");
        self.0.visit_map(ClaimsDe(map))
    }

    fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::EnumAccess<'de>,
    {
        self.0.visit_enum(data)
    }
}

#[cfg(test)]
mod tests {
    use super::ClaimsDe;

    #[test]
    fn deser() {
        let x = r#"{
            "aud": "foo",
            "nbf": "bar",
            "nested": {
                "baz": "blah"
            }
        }"#;

        let ClaimsDe(y): ClaimsDe<serde_json::Value> = serde_json::from_str(x).unwrap();
        dbg!(y);
    }
}
