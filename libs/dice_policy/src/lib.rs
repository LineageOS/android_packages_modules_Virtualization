/*
 * Copyright (C) 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! A “DICE policy” is a format for setting constraints on a DICE chain. A DICE chain policy
//! verifier takes a policy and a DICE chain, and returns a boolean indicating whether the
//! DICE chain meets the constraints set out on a policy.
//!
//! This forms the foundation of Dice Policy aware Authentication (DPA-Auth), where the server
//! authenticates a client by comparing its dice chain against a set policy.
//!
//! Another use is "sealing", where clients can use an appropriately constructed dice policy to
//! seal a secret. Unsealing is only permitted if dice chain of the component requesting unsealing
//! complies with the policy.
//!
//! A typical policy will assert things like:
//! # DK_pub must have this value
//! # The DICE chain must be exactly five certificates long
//! # authorityHash in the third certificate must have this value
//! securityVersion in the fourth certificate must be an integer greater than 8
//!
//! These constraints used to express policy are (for now) limited to following 2 types:
//! 1. Exact Match: useful for enforcing rules like authority hash should be exactly equal.
//! 2. Greater than or equal to: Useful for setting policies that seal
//! Anti-rollback protected entities (should be accessible to versions >= present).
//!
//! Dice Policy CDDL:
//!
//! dicePolicy = [
//! 1, ; dice policy version
//! + nodeConstraintList ; for each entry in dice chain
//! ]
//!
//! nodeConstraintList = [
//!     * nodeConstraint
//! ]
//!
//! ; We may add a hashConstraint item later
//! nodeConstraint = exactMatchConstraint / geConstraint
//!
//! exactMatchConstraint = [1, keySpec, value]
//! geConstraint = [2, keySpec, int]
//!
//! keySpec = [value+]
//!
//! value = bool / int / tstr / bstr

use anyhow::{anyhow, bail, Context, Result};
use ciborium::Value;
use coset::{AsCborValue, CoseSign1};
use std::borrow::Cow;

const DICE_POLICY_VERSION: u64 = 1;

/// Constraint Types supported in Dice policy.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ConstraintType {
    /// Enforce exact match criteria, indicating the policy should match
    /// if the dice chain has exact same specified values.
    ExactMatch = 1,
    /// Enforce Greater than or equal to criteria. When applied on security_version, this
    /// can be useful to set policy that matches dice chains with same or upgraded images.
    GreaterOrEqual = 2,
}

/// ConstraintSpec is used to specify which constraint type to apply and
/// on which all entries in a dice node.
/// See documentation of `from_dice_chain()` for examples.
pub struct ConstraintSpec {
    constraint_type: ConstraintType,
    // path is essentially a list of label/int.
    // It identifies which entry (in a dice node) to be applying constraints on.
    path: Vec<i64>,
}

impl ConstraintSpec {
    /// Construct the ConstraintSpec.
    pub fn new(constraint_type: ConstraintType, path: Vec<i64>) -> Result<Self> {
        Ok(ConstraintSpec { constraint_type, path })
    }
}

// TODO(b/291238565): Restrict (nested_)key & value type to (bool/int/tstr/bstr).
// and maybe convert it into struct.
/// Each constraint (on a dice node) is a tuple: (ConstraintType, constraint_path, value)
#[derive(Debug, PartialEq)]
struct Constraint(u16, Vec<i64>, Value);

/// List of all constraints on a dice node.
#[derive(Debug, PartialEq)]
struct NodeConstraints(Box<[Constraint]>);

/// Module for working with dice policy.
#[derive(Debug, PartialEq)]
pub struct DicePolicy {
    version: u64,
    node_constraints_list: Box<[NodeConstraints]>, // Constraint on each entry in dice chain.
}

impl DicePolicy {
    /// Construct a dice policy from a given dice chain.
    /// This can be used by clients to construct a policy to seal secrets.
    /// Constraints on all but first dice node is applied using constraint_spec argument.
    /// For the first node (which is a ROT key), the constraint is ExactMatch of the whole node.
    ///
    /// # Arguments
    /// `dice_chain`: The serialized CBOR encoded Dice chain, adhering to Android Profile for DICE.
    /// https://pigweed.googlesource.com/open-dice/+/refs/heads/main/docs/android.md
    ///
    /// `constraint_spec`: List of constraints to be applied on dice node.
    /// Each constraint is a ConstraintSpec object.
    ///
    /// Note: Dice node is treated as a nested map (& so the lookup is done in that fashion).
    ///
    /// Examples of constraint_spec:
    ///  1. For exact_match on auth_hash & greater_or_equal on security_version
    ///    constraint_spec =[
    ///     (ConstraintType::ExactMatch, vec![AUTHORITY_HASH]),
    ///     (ConstraintType::GreaterOrEqual, vec![CONFIG_DESC, COMPONENT_NAME]),
    ///    ];
    ///
    /// 2. For hypothetical (and highly simplified) dice chain:
    ///    [ROT_KEY, [{1 : 'a', 2 : {200 : 5, 201 : 'b'}}]]
    ///    The following can be used
    ///    constraint_spec =[
    ///     ConstraintSpec(ConstraintType::ExactMatch, vec![1]),         // exact_matches value 'a'
    ///     ConstraintSpec(ConstraintType::GreaterOrEqual, vec![2, 200]),// matches any value >= 5
    ///    ];
    pub fn from_dice_chain(dice_chain: &[u8], constraint_spec: &[ConstraintSpec]) -> Result<Self> {
        // TODO(b/298217847): Check if the given dice chain adheres to Explicit-key DiceCertChain
        // format and if not, convert it before policy construction.
        let dice_chain = value_from_bytes(dice_chain).context("Unable to decode top-level CBOR")?;
        let dice_chain = match dice_chain {
            Value::Array(array) if array.len() >= 2 => array,
            _ => bail!("Expected an array of at least length 2, found: {:?}", dice_chain),
        };
        let mut constraints_list: Vec<NodeConstraints> = Vec::with_capacity(dice_chain.len());
        let mut it = dice_chain.into_iter();

        constraints_list.push(NodeConstraints(Box::new([Constraint(
            ConstraintType::ExactMatch as u16,
            Vec::new(),
            it.next().unwrap(),
        )])));

        for (n, value) in it.enumerate() {
            let entry = cbor_value_from_cose_sign(value)
                .with_context(|| format!("Unable to get Cose payload at: {}", n))?;
            constraints_list.push(payload_to_constraints(entry, constraint_spec)?);
        }

        Ok(DicePolicy {
            version: DICE_POLICY_VERSION,
            node_constraints_list: constraints_list.into_boxed_slice(),
        })
    }
}

// Take the payload of a dice node & construct the constraints on it.
fn payload_to_constraints(
    payload: Value,
    constraint_spec: &[ConstraintSpec],
) -> Result<NodeConstraints> {
    let mut node_constraints: Vec<Constraint> = Vec::new();
    for constraint_item in constraint_spec {
        let constraint_path = constraint_item.path.to_vec();
        if constraint_path.is_empty() {
            bail!("Expected non-empty key spec");
        }
        let val = lookup_value_in_nested_map(&payload, &constraint_path)
            .context(format!("Value not found for constraint_path {:?}", constraint_path))?;
        let constraint = Constraint(constraint_item.constraint_type as u16, constraint_path, val);
        node_constraints.push(constraint);
    }
    Ok(NodeConstraints(node_constraints.into_boxed_slice()))
}

// Lookup value corresponding to constraint path in nested map.
// This function recursively calls itself.
// The depth of recursion is limited by the size of constraint_path.
fn lookup_value_in_nested_map(cbor_map: &Value, constraint_path: &[i64]) -> Result<Value> {
    if constraint_path.is_empty() {
        return Ok(cbor_map.clone());
    }
    let explicit_map = get_map_from_value(cbor_map)?;
    let val = lookup_value_in_map(&explicit_map, constraint_path[0])
        .ok_or(anyhow!("Value not found for constraint key: {:?}", constraint_path[0]))?;
    lookup_value_in_nested_map(val, &constraint_path[1..])
}

fn get_map_from_value(cbor_map: &Value) -> Result<Cow<Vec<(Value, Value)>>> {
    match cbor_map {
        Value::Bytes(b) => value_from_bytes(b)?
            .into_map()
            .map(Cow::Owned)
            .map_err(|e| anyhow!("Expected a cbor map: {:?}", e)),
        Value::Map(map) => Ok(Cow::Borrowed(map)),
        _ => bail!("/Expected a cbor map {:?}", cbor_map),
    }
}

fn lookup_value_in_map(map: &[(Value, Value)], key: i64) -> Option<&Value> {
    let key = Value::Integer(key.into());
    for (k, v) in map.iter() {
        if k == &key {
            return Some(v);
        }
    }
    None
}

/// Extract the payload from the COSE Sign
fn cbor_value_from_cose_sign(cbor: Value) -> Result<Value> {
    let sign1 =
        CoseSign1::from_cbor_value(cbor).map_err(|e| anyhow!("Error extracting CoseKey: {}", e))?;
    match sign1.payload {
        None => bail!("Missing payload"),
        Some(payload) => Ok(value_from_bytes(&payload)?),
    }
}

/// Decodes the provided binary CBOR-encoded value and returns a
/// ciborium::Value struct wrapped in Result.
fn value_from_bytes(mut bytes: &[u8]) -> Result<Value> {
    let value = ciborium::de::from_reader(&mut bytes)?;
    // Ciborium tries to read one Value, & doesn't care if there is trailing data after it. We do.
    if !bytes.is_empty() {
        bail!("Unexpected trailing data while converting to CBOR value");
    }
    Ok(value)
}

#[cfg(test)]
rdroidtest::test_main!();

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::cbor;
    use coset::{CoseKey, Header, ProtectedHeader};
    use rdroidtest::test;

    const AUTHORITY_HASH: i64 = -4670549;
    const CONFIG_DESC: i64 = -4670548;
    const COMPONENT_NAME: i64 = -70002;
    const KEY_MODE: i64 = -4670551;

    // This is the number of certs in compos bcc (including the first ROT)
    // To analyze a bcc use hwtrust tool from /tools/security/remote_provisioning/hwtrust
    // `hwtrust --verbose dice-chain [path]/composbcc`
    const COMPOS_DICE_CHAIN_SIZE: usize = 5;
    const EXAMPLE_STRING: &str = "testing_dice_policy";
    const EXAMPLE_NUM: i64 = 59765;

    test!(policy_dice_size_is_same);
    fn policy_dice_size_is_same() {
        let input_dice = include_bytes!("../testdata/composbcc");
        let constraint_spec = [
            ConstraintSpec::new(ConstraintType::ExactMatch, vec![AUTHORITY_HASH]).unwrap(),
            ConstraintSpec::new(ConstraintType::ExactMatch, vec![KEY_MODE]).unwrap(),
            ConstraintSpec::new(ConstraintType::GreaterOrEqual, vec![CONFIG_DESC, COMPONENT_NAME])
                .unwrap(),
        ];
        let policy = DicePolicy::from_dice_chain(input_dice, &constraint_spec).unwrap();
        assert_eq!(policy.node_constraints_list.len(), COMPOS_DICE_CHAIN_SIZE);
    }

    test!(policy_structure_check);
    fn policy_structure_check() {
        let rot_key = CoseKey::default().to_cbor_value().unwrap();
        let nested_payload = cbor!({
            100 => EXAMPLE_NUM
        })
        .unwrap();
        let payload = cbor!({
            1 => EXAMPLE_STRING,
            2 => "some_other_example_string",
            3 => Value::Bytes(value_to_bytes(&nested_payload).unwrap()),
        })
        .unwrap();
        let payload = value_to_bytes(&payload).unwrap();
        let dice_node = CoseSign1 {
            protected: ProtectedHeader::default(),
            unprotected: Header::default(),
            payload: Some(payload),
            signature: b"ddef".to_vec(),
        }
        .to_cbor_value()
        .unwrap();
        let input_dice = Value::Array([rot_key.clone(), dice_node].to_vec());

        let input_dice = value_to_bytes(&input_dice).unwrap();
        let constraint_spec = [
            ConstraintSpec::new(ConstraintType::ExactMatch, vec![1]).unwrap(),
            ConstraintSpec::new(ConstraintType::GreaterOrEqual, vec![3, 100]).unwrap(),
        ];
        let policy = DicePolicy::from_dice_chain(&input_dice, &constraint_spec).unwrap();

        // Assert policy is exactly as expected!
        assert_eq!(
            policy,
            DicePolicy {
                version: 1,
                node_constraints_list: Box::new([
                    NodeConstraints(Box::new([Constraint(
                        ConstraintType::ExactMatch as u16,
                        vec![],
                        rot_key
                    )])),
                    NodeConstraints(Box::new([
                        Constraint(
                            ConstraintType::ExactMatch as u16,
                            vec![1],
                            Value::Text(EXAMPLE_STRING.to_string())
                        ),
                        Constraint(
                            ConstraintType::GreaterOrEqual as u16,
                            vec![3, 100],
                            Value::from(EXAMPLE_NUM)
                        )
                    ])),
                ])
            }
        );
    }

    /// Encodes a ciborium::Value into bytes.
    fn value_to_bytes(value: &Value) -> Result<Vec<u8>> {
        let mut bytes: Vec<u8> = Vec::new();
        ciborium::ser::into_writer(&value, &mut bytes)?;
        Ok(bytes)
    }
}
