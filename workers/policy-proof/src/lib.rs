use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use cedar_policy::{
    Authorizer, Context, Decision, Entities, PolicySet, Request, Schema, ValidationMode, Validator,
};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

pub const PROGRAM: &str = "passport.hidden-limit.bp5.ristretto.32x2.v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitInput {
    pub limit: u32,
}
#[derive(Serialize)]
pub struct Commitment {
    pub commitment: String,
    pub blinding: String,
}
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ProofInput {
    pub program: String,
    pub commitment: String,
    pub amount_minor_units: u32,
    pub context_digest: String,
    pub proof: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProveInput {
    pub program: String,
    pub commitment: String,
    pub amount_minor_units: u32,
    pub context_digest: String,
    pub limit: u32,
    pub blinding: String,
}
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DecisionInput {
    pub agent_id: String,
    pub action: String,
    pub resource: String,
    pub audience: String,
    pub recipient: String,
    pub currency: String,
    pub asset: String,
    pub network: String,
    pub amount_minor_units: u32,
    pub limit: u32,
}

fn bytes32(s: &str) -> Result<[u8; 32], &'static str> {
    hex::decode(s)
        .map_err(|_| "invalid_encoding")?
        .try_into()
        .map_err(|_| "invalid_encoding")
}
fn transcript(
    program: &str,
    commitment: &str,
    amount: u32,
    digest: &str,
) -> Result<Transcript, &'static str> {
    if program != PROGRAM {
        return Err("invalid_program");
    }
    let mut t = Transcript::new(b"passport.hidden-limit.v1");
    t.append_message(b"program", PROGRAM.as_bytes());
    t.append_message(b"commitment", &bytes32(commitment)?);
    t.append_message(b"amount", &amount.to_le_bytes());
    t.append_message(b"capability_digest", &bytes32(digest)?);
    Ok(t)
}
pub fn commit(limit: u32) -> Commitment {
    let blinding = Scalar::random(&mut rand::thread_rng());
    let commitment = PedersenGens::default()
        .commit(Scalar::from(limit as u64), blinding)
        .compress();
    Commitment {
        commitment: hex::encode(commitment.as_bytes()),
        blinding: hex::encode(blinding.as_bytes()),
    }
}
pub fn prove(i: &ProveInput) -> Result<String, &'static str> {
    let remainder = i.limit.checked_sub(i.amount_minor_units).ok_or("denied")?;
    let blinding = Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes32(&i.blinding)?))
        .ok_or("invalid_encoding")?;
    let pc = PedersenGens::default();
    if hex::encode(
        pc.commit(Scalar::from(i.limit as u64), blinding)
            .compress()
            .as_bytes(),
    ) != i.commitment
    {
        return Err("policy_mismatch");
    }
    let mut t = transcript(
        &i.program,
        &i.commitment,
        i.amount_minor_units,
        &i.context_digest,
    )?;
    let (proof, _) = RangeProof::prove_multiple(
        &BulletproofGens::new(32, 2),
        &pc,
        &mut t,
        &[i.limit as u64, remainder as u64],
        &[blinding, blinding],
        32,
    )
    .map_err(|_| "invalid_proof")?;
    Ok(hex::encode(proof.to_bytes()))
}
pub fn verify(i: &ProofInput) -> Result<bool, &'static str> {
    let pc = PedersenGens::default();
    let c = CompressedRistretto(bytes32(&i.commitment)?);
    let point = c.decompress().ok_or("invalid_encoding")?;
    let difference = (point - Scalar::from(i.amount_minor_units as u64) * pc.B).compress();
    let mut t = transcript(
        &i.program,
        &i.commitment,
        i.amount_minor_units,
        &i.context_digest,
    )?;
    let proof = RangeProof::from_bytes(&hex::decode(&i.proof).map_err(|_| "invalid_encoding")?)
        .map_err(|_| "invalid_proof")?;
    Ok(proof
        .verify_multiple(
            &BulletproofGens::new(32, 2),
            &pc,
            &mut t,
            &[c, difference],
            32,
        )
        .is_ok())
}
pub fn validated_policy() -> Result<(PolicySet, Schema), String> {
    let policy: PolicySet = include_str!("../policy.cedar")
        .parse()
        .map_err(|e| format!("{e}"))?;
    let schema =
        Schema::from_json_str(include_str!("../schema.json")).map_err(|e| format!("{e}"))?;
    let validation = Validator::new(schema.clone()).validate(&policy, ValidationMode::Strict);
    if !validation.validation_passed() {
        return Err("Cedar schema validation failed".into());
    }
    Ok((policy, schema))
}
pub fn decide(i: &DecisionInput) -> Result<bool, String> {
    let (policy, schema) = validated_policy()?;
    let entity = |kind: &str, id: &str| {
        format!("{kind}::{}", serde_json::to_string(id).unwrap())
            .parse()
            .map_err(|e| format!("{e}"))
    };
    let context = Context::from_json_value(
        serde_json::json!({
            "audience":i.audience,"recipient":i.recipient,"currency":i.currency,
            "asset":i.asset,"network":i.network,"amount":i.amount_minor_units,"limit":i.limit
        }),
        None,
    )
    .map_err(|e| format!("{e}"))?;
    let req = Request::new(
        entity("Agent", &i.agent_id)?,
        entity("Action", &i.action)?,
        entity("Resource", &i.resource)?,
        context,
        Some(&schema),
    )
    .map_err(|e| format!("{e}"))?;
    let answer = Authorizer::new().is_authorized(&req, &policy, &Entities::empty());
    Ok(answer.decision() == Decision::Allow && answer.diagnostics().errors().next().is_none())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hidden_limit_and_binding() {
        let c = commit(5000);
        let i = ProveInput {
            program: PROGRAM.into(),
            commitment: c.commitment.clone(),
            amount_minor_units: 1200,
            context_digest: "ab".repeat(32),
            limit: 5000,
            blinding: c.blinding,
        };
        let mut v = ProofInput {
            program: PROGRAM.into(),
            commitment: c.commitment,
            amount_minor_units: 1200,
            context_digest: i.context_digest.clone(),
            proof: prove(&i).unwrap(),
        };
        assert!(verify(&v).unwrap());
        v.amount_minor_units = 1201;
        assert!(!verify(&v).unwrap());
        v.amount_minor_units = 1200;
        v.context_digest = "cd".repeat(32);
        assert!(!verify(&v).unwrap());
        v.context_digest = i.context_digest;
        v.commitment = commit(5000).commitment;
        assert!(!verify(&v).unwrap());
    }
    #[test]
    fn cedar_conforms_at_boundaries() {
        for limit in [1, 100, 5000, u32::MAX] {
            for amount in [0, 1, limit, limit.saturating_add(1)] {
                let decision = decide(&DecisionInput {
                    agent_id: "codex".into(),
                    action: "purchase".into(),
                    resource: "globex:research-report".into(),
                    audience: "globex".into(),
                    recipient: "globex".into(),
                    currency: "USD".into(),
                    asset: "iso4217:USD".into(),
                    network: "simulation".into(),
                    amount_minor_units: amount,
                    limit,
                })
                .unwrap();
                assert_eq!(decision, amount > 0 && amount <= limit);
                let c = commit(limit);
                let i = ProveInput {
                    program: PROGRAM.into(),
                    commitment: c.commitment,
                    amount_minor_units: amount,
                    context_digest: "11".repeat(32),
                    limit,
                    blinding: c.blinding,
                };
                if amount > limit {
                    assert!(prove(&i).is_err());
                } else if amount > 0 {
                    let proof = prove(&i).unwrap();
                    assert!(
                        verify(&ProofInput {
                            program: PROGRAM.into(),
                            commitment: i.commitment.clone(),
                            amount_minor_units: amount,
                            context_digest: i.context_digest.clone(),
                            proof,
                        })
                        .unwrap()
                    );
                }
            }
        }
    }
    #[test]
    fn commitment_hides_low_entropy_values() {
        assert_ne!(commit(100).commitment, commit(100).commitment);
    }
}
