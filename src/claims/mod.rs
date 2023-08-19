//! PASETO Claims and validators

use std::borrow::Cow;

use serde::{
    de::{self, DeserializeSeed, MapAccess, Visitor},
    forward_to_deserialize_any, Deserialize, Deserializer,
};
use time::OffsetDateTime;

pub enum PasetoValueType {
    String,
    DateTime,
}
pub enum PasetoValue<'a> {
    String(&'a str),
    DateTime(OffsetDateTime),
}

pub trait Validator {
    fn validates_claim(&self, field: &str) -> Option<PasetoValueType>;
    #[allow(clippy::result_unit_err)]
    fn validate(&self, field: &str, value: PasetoValue<'_>) -> Result<(), ()>;
}

pub const ISSUER: &str = "iss";
pub const SUBJECT: &str = "sub";
pub const AUDIENCE: &str = "aud";
pub const EXPIRATION: &str = "exp";
pub const NOT_BEFORE: &str = "nbf";
pub const ISSUED_AT: &str = "iat";
pub const TOKEN_IDENTIFIER: &str = "jti";

pub struct NotExpired(pub OffsetDateTime);

impl Validator for NotExpired {
    fn validates_claim(&self, field: &str) -> Option<PasetoValueType> {
        const FIELDS: &[&str] = &[EXPIRATION];
        FIELDS.contains(&field).then_some(PasetoValueType::DateTime)
    }

    fn validate(&self, field: &str, value: PasetoValue<'_>) -> Result<(), ()> {
        enum Order {
            LessThan,
            GreaterThan,
        }

        let order = match field {
            EXPIRATION => Order::LessThan,
            NOT_BEFORE => Order::GreaterThan,
            ISSUED_AT => Order::GreaterThan,
            _ => return Ok(()),
        };

        let dt = match value {
            PasetoValue::DateTime(dt) => dt,
            _ => return Err(()),
        };

        let valid = match order {
            Order::LessThan => self.0 <= dt,
            Order::GreaterThan => self.0 >= dt,
        };

        if valid {
            Ok(())
        } else {
            Err(())
        }
    }
}
pub struct ValidAt(pub OffsetDateTime);

impl Validator for ValidAt {
    fn validates_claim(&self, field: &str) -> Option<PasetoValueType> {
        const FIELDS: &[&str] = &[EXPIRATION, NOT_BEFORE, ISSUED_AT];
        FIELDS.contains(&field).then_some(PasetoValueType::DateTime)
    }

    fn validate(&self, field: &str, value: PasetoValue<'_>) -> Result<(), ()> {
        enum Order {
            LessThan,
            GreaterThan,
        }

        let order = match field {
            EXPIRATION => Order::LessThan,
            NOT_BEFORE => Order::GreaterThan,
            ISSUED_AT => Order::GreaterThan,
            _ => return Ok(()),
        };

        let dt = match value {
            PasetoValue::DateTime(dt) => dt,
            _ => return Err(()),
        };

        let valid = match order {
            Order::LessThan => self.0 <= dt,
            Order::GreaterThan => self.0 >= dt,
        };

        if valid {
            Ok(())
        } else {
            Err(())
        }
    }
}

/// Only deserializes maps
struct MapDeserializer<D>(D);

impl<'de, D> Deserializer<'de> for MapDeserializer<D>
where
    D: Deserializer<'de>,
{
    type Error = D::Error;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.0.deserialize_map(MapVisitor(visitor))
    }

    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct tuple_struct map
        seq tuple struct enum identifier ignored_any
    }
}

/// Only visits maps
struct MapVisitor<V>(V);

impl<'de, V> Visitor<'de> for MapVisitor<V>
where
    V: Visitor<'de>,
{
    type Value = V::Value;

    fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        self.0.visit_map(ClaimsDe {
            inner: map,
            key: None,
        })
    }

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.0.expecting(formatter)
    }
}

/// Only deserializes strs
struct StrDeserializer<'a, 'de, D> {
    inner: D,
    output: &'a mut Option<Cow<'de, str>>,
}

impl<'a, 'de, D> Deserializer<'de> for StrDeserializer<'a, 'de, D>
where
    D: Deserializer<'de>,
{
    type Error = D::Error;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.inner.deserialize_str(StrVisitor {
            inner: visitor,
            output: self.output,
        })
    }

    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct tuple_struct map
        seq tuple struct enum identifier ignored_any
    }
}

/// Only deserializes strs
struct StrVisitor<'a, 'de, V> {
    inner: V,
    output: &'a mut Option<Cow<'de, str>>,
}

impl<'a, 'de: 'a, V> Visitor<'de> for StrVisitor<'a, 'de, V>
where
    V: Visitor<'de>,
{
    type Value = V::Value;

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        *self.output = Some(v.to_owned().into());
        self.inner.visit_str(v)
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        *self.output = Some(v.into());
        self.inner.visit_borrowed_str(v)
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        *self.output = Some(v.clone().into());
        self.inner.visit_string(v)
    }

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.inner.expecting(formatter)
    }
}

/// PASETO Claims deserializer
///
/// forwards deserialization to the inner, but also extracts out relevant registered claims
struct ClaimsDe<'de, D> {
    inner: D,
    key: Option<Cow<'de, str>>,
}

// impl<'de, D> Deserializer<'de> for ClaimsDe<D>
// where
//     D: Deserializer<'de>,
// {
//     type Error = D::Error;

//     fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0.deserialize_any(PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0.deserialize_bool(PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0.deserialize_i8(PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0.deserialize_i16(PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0.deserialize_i32(PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0.deserialize_i64(PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0.deserialize_u8(PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0.deserialize_u16(PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0.deserialize_u32(PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0.deserialize_u64(PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_f32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0.deserialize_f32(PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_f64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0.deserialize_f64(PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_char<V>(self, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0.deserialize_char(PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         dbg!("deserialize_str");
//         self.0.deserialize_str(PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         dbg!("deserialize_string");
//         self.0.deserialize_string(PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0.deserialize_bytes(PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0.deserialize_byte_buf(PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0.deserialize_option(PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0.deserialize_unit(PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_unit_struct<V>(
//         self,
//         name: &'static str,
//         visitor: V,
//     ) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0
//             .deserialize_unit_struct(name, PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_newtype_struct<V>(
//         self,
//         name: &'static str,
//         visitor: V,
//     ) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0
//             .deserialize_newtype_struct(name, PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0.deserialize_seq(PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_tuple<V>(self, len: usize, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0.deserialize_tuple(len, PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_tuple_struct<V>(
//         self,
//         name: &'static str,
//         len: usize,
//         visitor: V,
//     ) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0
//             .deserialize_tuple_struct(name, len, PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_map<V>(self, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0.deserialize_map(PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_struct<V>(
//         self,
//         name: &'static str,
//         fields: &'static [&'static str],
//         visitor: V,
//     ) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0
//             .deserialize_struct(name, fields, PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_enum<V>(
//         self,
//         name: &'static str,
//         variants: &'static [&'static str],
//         visitor: V,
//     ) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0
//             .deserialize_enum(name, variants, PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0.deserialize_identifier(PasetoClaimVisitor(visitor))
//     }

//     fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
//     where
//         V: Visitor<'de>,
//     {
//         self.0.deserialize_ignored_any(PasetoClaimVisitor(visitor))
//     }
// }

impl<'a, 'de, Ds> DeserializeSeed<'de> for StrDeserializer<'a, 'de, Ds>
where
    Ds: DeserializeSeed<'de>,
{
    type Value = Ds::Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        self.inner.deserialize(StrDeserializer {
            inner: deserializer,
            output: self.output,
        })
    }
}

impl<'de, D> MapAccess<'de> for ClaimsDe<'de, D>
where
    D: MapAccess<'de>,
{
    type Error = D::Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
    where
        K: serde::de::DeserializeSeed<'de>,
    {
        if self.key.is_some() {
            return Err(de::Error::custom("map deserialize in an invalid state"));
        }
        self.inner.next_key_seed(StrDeserializer {
            inner: seed,
            output: &mut self.key,
        })
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
    where
        V: serde::de::DeserializeSeed<'de>,
    {
        dbg!(self.key.as_deref());
        if let Some(key) = self.key.take() {
            todo!()
        } else {
            self.inner.next_value_seed(seed)
        }
    }

    fn size_hint(&self) -> Option<usize> {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use crate::claims::MapDeserializer;

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

        let mut de = serde_json::Deserializer::from_str(x);
        let de = MapDeserializer(&mut de);
        let y = serde_json::Value::deserialize(de).unwrap();
        dbg!(y);
    }
}
