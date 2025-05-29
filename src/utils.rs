use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::hash::Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub(crate) fn ark_se<S, A: CanonicalSerialize>(a: &A, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut bytes = vec![];
    a.serialize_with_mode(&mut bytes, Compress::Yes)
        .map_err(serde::ser::Error::custom)?;
    s.serialize_bytes(&bytes)
}

pub(crate) fn ark_de<'de, D, A: CanonicalDeserialize>(data: D) -> Result<A, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s: Vec<u8> = serde::de::Deserialize::deserialize(data)?;
    let a = A::deserialize_with_mode(s.as_slice(), Compress::Yes, Validate::No);
    a.map_err(serde::de::Error::custom)
}

pub(crate) fn ark_map_se<S, G>(map: &HashMap<G, usize>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    G: CanonicalSerialize,
{
    // serialise each (key,value) -> (Vec<u8>, usize)
    let mut tmp: Vec<(Vec<u8>, usize)> = Vec::with_capacity(map.len());

    for (k, v) in map {
        let mut bytes = Vec::new();
        k.serialize_with_mode(&mut bytes, Compress::Yes)
            .map_err(serde::ser::Error::custom)?;
        tmp.push((bytes, *v));
    }

    // optional but *highly* recommended if “deterministic encoding”
    // actually matters for you: sort by the byte string
    tmp.sort_by(|a, b| a.0.cmp(&b.0));

    tmp.serialize(s)
}

pub(crate) fn ark_map_de<'de, D, G>(d: D) -> Result<HashMap<G, usize>, D::Error>
where
    D: serde::Deserializer<'de>,
    G: CanonicalDeserialize + Eq + Hash,
{
    let pairs: Vec<(Vec<u8>, usize)> = Vec::<(Vec<u8>, usize)>::deserialize(d)?;
    let mut map = HashMap::with_capacity(pairs.len());

    for (bytes, val) in pairs {
        let key = G::deserialize_with_mode(bytes.as_slice(), Compress::Yes, Validate::No)
            .map_err(serde::de::Error::custom)?;
        if map.insert(key, val).is_some() {
            return Err(serde::de::Error::custom("duplicate key in input"));
        }
    }

    Ok(map)
}
