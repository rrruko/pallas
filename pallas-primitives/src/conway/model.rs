//! Ledger primitives and cbor codec for the Conway era
//!
//! Handcrafted, idiomatic rust artifacts based on based on the [Conway CDDL](https://github.com/IntersectMBO/cardano-ledger/blob/master/eras/conway/impl/cddl-files/conway.cddl) file in IntersectMBO repo.

use std::collections::BTreeMap;
use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use pallas_codec::minicbor::{self, Decode, Encode};
use pallas_codec::utils::CborWrap;

pub use crate::{
    plutus_data::*, AddrKeyhash, AssetName, Bytes, Coin, CostModel, DnsName, Epoch, ExUnits,
    GenesisDelegateHash, Genesishash, Hash, IPv4, IPv6, KeepRaw, KeyValuePairs, MaybeIndefArray,
    Metadata, Metadatum, MetadatumLabel, NetworkId, NonEmptyKeyValuePairs, NonEmptySet, NonZeroInt,
    Nonce, NonceVariant, Nullable, PlutusScript, PolicyId, PoolKeyhash, PoolMetadata,
    PoolMetadataHash, Port, PositiveCoin, PositiveInterval, ProtocolVersion, RationalNumber, Relay,
    RewardAccount, ScriptHash, Set, StakeCredential, TransactionIndex, TransactionInput,
    UnitInterval, VrfCert, VrfKeyhash,
};

use crate::minicbor::data::Type;

use crate::babbage;

pub use crate::babbage::HeaderBody;

pub use crate::babbage::OperationalCert;

pub use crate::babbage::Header;

pub type Multiasset<A> = NonEmptyKeyValuePairs<PolicyId, NonEmptyKeyValuePairs<AssetName, A>>;

pub type Mint = Multiasset<NonZeroInt>;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum Value {
    Coin(Coin),
    Multiasset(Coin, Multiasset<PositiveCoin>),
}

impl<C> minicbor::Encode<C> for Value {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Value::Coin(coin) => {
                e.encode(coin)?;
            },
            Value::Multiasset(coin, ma) => {
                e.array(2)?;
                e.encode(coin)?;
                e.encode(ma)?;
            }
        }
        Ok(())
    }
}

impl<'b, Ctx> minicbor::Decode<'b, Ctx> for Value
where
    Ctx: ValidationContext
{
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut Ctx) -> Result<Self, minicbor::decode::Error> {
        match d.datatype()? {
            Type::U8 | Type::U16 | Type::U32 | Type::U64 => {
                let coin = d.decode_with(ctx)?;
                Ok(Value::Coin(coin))
            }
            Type::Array | Type::ArrayIndef => {
                let _ = d.array()?;
                let coin = d.decode_with(ctx)?;
                let multiasset = d.decode_with(ctx)?;
                Ok(Value::Multiasset(coin, multiasset))
            }
            t => {
                Err(minicbor::decode::Error::message(format!("Unexpected datatype {}", t)))
            }
        }
    }
}

pub trait ValidationContext {
    fn push_error(&mut self, s: String) -> Result<(), minicbor::decode::Error>;
    fn get_errors(&self) -> &[String];
}

impl ValidationContext for () {
    fn push_error(&mut self, _s: String) -> Result<(), minicbor::decode::Error> {
        Ok(())
    }
    fn get_errors(&self) -> &[String] {
        &[]
    }
}

pub struct AccumulatingContext {
    errors: Vec<String>,
}

impl AccumulatingContext {
    pub fn new() -> Self {
        AccumulatingContext {
            errors: vec![]
        }
    }
}

impl ValidationContext for AccumulatingContext {
    fn push_error(&mut self, s: String) -> Result<(), minicbor::decode::Error> {
        self.errors.push(s);
        Ok(())
    }
    fn get_errors(&self) -> &[String] {
        &self.errors
    }
}

pub struct TerminatingContext {
}

impl TerminatingContext {
    pub fn new() -> Self {
        TerminatingContext {
        }
    }
}

impl ValidationContext for TerminatingContext {
    fn push_error(&mut self, s: String) -> Result<(), minicbor::decode::Error> {
        Err(minicbor::decode::Error::message(format!("Failed strict validation: {}", s)))
    }
    fn get_errors(&self) -> &[String] {
        &[]
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Strict<T> {
    inner: T,
}

impl<T> Strict<T> {
    pub fn unwrap(self) -> T {
        self.inner
    }
}

impl<'b, T, C> minicbor::Decode<'b, C> for Strict<T>
where
    T: minicbor::Decode<'b, TerminatingContext>
{
    fn decode(d: &mut minicbor::Decoder<'b>, _ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let mut ctx = TerminatingContext::new();
        let inner: T = d.decode_with(&mut ctx)?;
        Ok(Strict {
            inner
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct StrictVerbose<T> {
    inner: T,
}

impl<T> StrictVerbose<T> {
    pub fn unwrap(self) -> T {
        self.inner
    }
}

impl<'b, T, C> minicbor::Decode<'b, C> for StrictVerbose<T>
where
    T: minicbor::Decode<'b, AccumulatingContext>
{
    fn decode(d: &mut minicbor::Decoder<'b>, _ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let mut ctx = AccumulatingContext::new();
        let inner: T = d.decode_with(&mut ctx)?;
        let errs = ctx.get_errors();
        if !errs.is_empty() {
            let s = errs.join(";");
            return Err(minicbor::decode::Error::message(
                    format!("Failed strict validation: {}", s)
            ));
        }
        Ok(StrictVerbose {
            inner
        })
    }
}

pub use crate::alonzo::TransactionOutput as LegacyTransactionOutput;

pub type Withdrawals = NonEmptyKeyValuePairs<RewardAccount, Coin>;

pub type RequiredSigners = NonEmptySet<AddrKeyhash>;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum Certificate {
    StakeRegistration(StakeCredential),
    StakeDeregistration(StakeCredential),
    StakeDelegation(StakeCredential, PoolKeyhash),
    PoolRegistration {
        operator: PoolKeyhash,
        vrf_keyhash: VrfKeyhash,
        pledge: Coin,
        cost: Coin,
        margin: UnitInterval,
        reward_account: RewardAccount,
        pool_owners: Set<AddrKeyhash>,
        relays: Vec<Relay>,
        pool_metadata: Nullable<PoolMetadata>,
    },
    PoolRetirement(PoolKeyhash, Epoch),

    Reg(StakeCredential, Coin),
    UnReg(StakeCredential, Coin),
    VoteDeleg(StakeCredential, DRep),
    StakeVoteDeleg(StakeCredential, PoolKeyhash, DRep),
    StakeRegDeleg(StakeCredential, PoolKeyhash, Coin),
    VoteRegDeleg(StakeCredential, DRep, Coin),
    StakeVoteRegDeleg(StakeCredential, PoolKeyhash, DRep, Coin),

    AuthCommitteeHot(CommitteeColdCredential, CommitteeHotCredential),
    ResignCommitteeCold(CommitteeColdCredential, Nullable<Anchor>),
    RegDRepCert(DRepCredential, Coin, Nullable<Anchor>),
    UnRegDRepCert(DRepCredential, Coin),
    UpdateDRepCert(DRepCredential, Nullable<Anchor>),
}

impl<'b, C> minicbor::decode::Decode<'b, C> for Certificate {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        d.array()?;
        let variant = d.u16()?;

        match variant {
            0 => {
                let a = d.decode_with(ctx)?;
                Ok(Certificate::StakeRegistration(a))
            }
            1 => {
                let a = d.decode_with(ctx)?;
                Ok(Certificate::StakeDeregistration(a))
            }
            2 => {
                let a = d.decode_with(ctx)?;
                let b = d.decode_with(ctx)?;
                Ok(Certificate::StakeDelegation(a, b))
            }
            3 => {
                let operator = d.decode_with(ctx)?;
                let vrf_keyhash = d.decode_with(ctx)?;
                let pledge = d.decode_with(ctx)?;
                let cost = d.decode_with(ctx)?;
                let margin = d.decode_with(ctx)?;
                let reward_account = d.decode_with(ctx)?;
                let pool_owners = d.decode_with(ctx)?;
                let relays = d.decode_with(ctx)?;
                let pool_metadata = d.decode_with(ctx)?;

                Ok(Certificate::PoolRegistration {
                    operator,
                    vrf_keyhash,
                    pledge,
                    cost,
                    margin,
                    reward_account,
                    pool_owners,
                    relays,
                    pool_metadata,
                })
            }
            4 => {
                let a = d.decode_with(ctx)?;
                let b = d.decode_with(ctx)?;
                Ok(Certificate::PoolRetirement(a, b))
            }

            7 => {
                let a = d.decode_with(ctx)?;
                let b = d.decode_with(ctx)?;
                Ok(Certificate::Reg(a, b))
            }
            8 => {
                let a = d.decode_with(ctx)?;
                let b = d.decode_with(ctx)?;
                Ok(Certificate::UnReg(a, b))
            }
            9 => {
                let a = d.decode_with(ctx)?;
                let b = d.decode_with(ctx)?;
                Ok(Certificate::VoteDeleg(a, b))
            }
            10 => {
                let a = d.decode_with(ctx)?;
                let b = d.decode_with(ctx)?;
                let c = d.decode_with(ctx)?;
                Ok(Certificate::StakeVoteDeleg(a, b, c))
            }
            11 => {
                let a = d.decode_with(ctx)?;
                let b = d.decode_with(ctx)?;
                let c = d.decode_with(ctx)?;
                Ok(Certificate::StakeRegDeleg(a, b, c))
            }
            12 => {
                let a = d.decode_with(ctx)?;
                let b = d.decode_with(ctx)?;
                let c = d.decode_with(ctx)?;
                Ok(Certificate::VoteRegDeleg(a, b, c))
            }
            13 => {
                let a = d.decode_with(ctx)?;
                let b = d.decode_with(ctx)?;
                let c = d.decode_with(ctx)?;
                let d = d.decode_with(ctx)?;
                Ok(Certificate::StakeVoteRegDeleg(a, b, c, d))
            }
            14 => {
                let a = d.decode_with(ctx)?;
                let b = d.decode_with(ctx)?;
                Ok(Certificate::AuthCommitteeHot(a, b))
            }
            15 => {
                let a = d.decode_with(ctx)?;
                let b = d.decode_with(ctx)?;
                Ok(Certificate::ResignCommitteeCold(a, b))
            }
            16 => {
                let a = d.decode_with(ctx)?;
                let b = d.decode_with(ctx)?;
                let c = d.decode_with(ctx)?;
                Ok(Certificate::RegDRepCert(a, b, c))
            }
            17 => {
                let a = d.decode_with(ctx)?;
                let b = d.decode_with(ctx)?;
                Ok(Certificate::UnRegDRepCert(a, b))
            }
            18 => {
                let a = d.decode_with(ctx)?;
                let b = d.decode_with(ctx)?;
                Ok(Certificate::UpdateDRepCert(a, b))
            }
            _ => Err(minicbor::decode::Error::message(
                "unknown variant id for certificate",
            )),
        }
    }
}

impl<C> minicbor::encode::Encode<C> for Certificate {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Certificate::StakeRegistration(a) => {
                e.array(2)?;
                e.u16(0)?;
                e.encode_with(a, ctx)?;
            }
            Certificate::StakeDeregistration(a) => {
                e.array(2)?;
                e.u16(1)?;
                e.encode_with(a, ctx)?;
            }
            Certificate::StakeDelegation(a, b) => {
                e.array(3)?;
                e.u16(2)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
            }
            Certificate::PoolRegistration {
                operator,
                vrf_keyhash,
                pledge,
                cost,
                margin,
                reward_account,
                pool_owners,
                relays,
                pool_metadata,
            } => {
                e.array(10)?;
                e.u16(3)?;

                e.encode_with(operator, ctx)?;
                e.encode_with(vrf_keyhash, ctx)?;
                e.encode_with(pledge, ctx)?;
                e.encode_with(cost, ctx)?;
                e.encode_with(margin, ctx)?;
                e.encode_with(reward_account, ctx)?;
                e.encode_with(pool_owners, ctx)?;
                e.encode_with(relays, ctx)?;
                e.encode_with(pool_metadata, ctx)?;
            }
            Certificate::PoolRetirement(a, b) => {
                e.array(3)?;
                e.u16(4)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
            }
            // 5 and 6 removed in conway
            Certificate::Reg(a, b) => {
                e.array(3)?;
                e.u16(7)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
            }
            Certificate::UnReg(a, b) => {
                e.array(3)?;
                e.u16(8)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
            }
            Certificate::VoteDeleg(a, b) => {
                e.array(3)?;
                e.u16(9)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
            }
            Certificate::StakeVoteDeleg(a, b, c) => {
                e.array(4)?;
                e.u16(10)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
                e.encode_with(c, ctx)?;
            }
            Certificate::StakeRegDeleg(a, b, c) => {
                e.array(4)?;
                e.u16(11)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
                e.encode_with(c, ctx)?;
            }
            Certificate::VoteRegDeleg(a, b, c) => {
                e.array(4)?;
                e.u16(12)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
                e.encode_with(c, ctx)?;
            }
            Certificate::StakeVoteRegDeleg(a, b, c, d) => {
                e.array(5)?;
                e.u16(13)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
                e.encode_with(c, ctx)?;
                e.encode_with(d, ctx)?;
            }
            Certificate::AuthCommitteeHot(a, b) => {
                e.array(3)?;
                e.u16(14)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
            }
            Certificate::ResignCommitteeCold(a, b) => {
                e.array(3)?;
                e.u16(15)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
            }
            Certificate::RegDRepCert(a, b, c) => {
                e.array(4)?;
                e.u16(16)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
                e.encode_with(c, ctx)?;
            }
            Certificate::UnRegDRepCert(a, b) => {
                e.array(3)?;
                e.u16(17)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
            }
            Certificate::UpdateDRepCert(a, b) => {
                e.array(3)?;
                e.u16(18)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
            }
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, PartialOrd, Eq, Ord, Clone)]
pub enum DRep {
    Key(AddrKeyhash),
    Script(ScriptHash),
    Abstain,
    NoConfidence,
}

impl<'b, C> minicbor::decode::Decode<'b, C> for DRep {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        d.array()?;
        let variant = d.u16()?;

        match variant {
            0 => Ok(DRep::Key(d.decode_with(ctx)?)),
            1 => Ok(DRep::Script(d.decode_with(ctx)?)),
            2 => Ok(DRep::Abstain),
            3 => Ok(DRep::NoConfidence),
            _ => Err(minicbor::decode::Error::message(
                "invalid variant id for DRep",
            )),
        }
    }
}

impl<C> minicbor::encode::Encode<C> for DRep {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            DRep::Key(h) => {
                e.array(2)?;
                e.encode_with(0, ctx)?;
                e.encode_with(h, ctx)?;

                Ok(())
            }
            DRep::Script(h) => {
                e.array(2)?;
                e.encode_with(1, ctx)?;
                e.encode_with(h, ctx)?;

                Ok(())
            }
            DRep::Abstain => {
                e.array(1)?;
                e.encode_with(2, ctx)?;

                Ok(())
            }
            DRep::NoConfidence => {
                e.array(1)?;
                e.encode_with(3, ctx)?;

                Ok(())
            }
        }
    }
}

pub type DRepCredential = StakeCredential;

pub type CommitteeColdCredential = StakeCredential;

pub type CommitteeHotCredential = StakeCredential;

#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone)]
#[cbor(index_only)]
pub enum Language {
    #[n(0)]
    PlutusV1,

    #[n(1)]
    PlutusV2,

    #[n(2)]
    PlutusV3,
}

#[deprecated(since = "0.31.0", note = "use `CostModels` instead")]
pub type CostMdls = CostModels;

#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone)]
#[cbor(map)]
pub struct CostModels {
    #[n(0)]
    pub plutus_v1: Option<CostModel>,

    #[n(1)]
    pub plutus_v2: Option<CostModel>,

    #[n(2)]
    pub plutus_v3: Option<CostModel>,
}

#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone)]
#[cbor(map)]
pub struct ProtocolParamUpdate {
    #[n(0)]
    pub minfee_a: Option<u64>,
    #[n(1)]
    pub minfee_b: Option<u64>,
    #[n(2)]
    pub max_block_body_size: Option<u64>,
    #[n(3)]
    pub max_transaction_size: Option<u64>,
    #[n(4)]
    pub max_block_header_size: Option<u64>,
    #[n(5)]
    pub key_deposit: Option<Coin>,
    #[n(6)]
    pub pool_deposit: Option<Coin>,
    #[n(7)]
    pub maximum_epoch: Option<Epoch>,
    #[n(8)]
    pub desired_number_of_stake_pools: Option<u64>,
    #[n(9)]
    pub pool_pledge_influence: Option<RationalNumber>,
    #[n(10)]
    pub expansion_rate: Option<UnitInterval>,
    #[n(11)]
    pub treasury_growth_rate: Option<UnitInterval>,

    #[n(16)]
    pub min_pool_cost: Option<Coin>,
    #[n(17)]
    pub ada_per_utxo_byte: Option<Coin>,
    #[n(18)]
    pub cost_models_for_script_languages: Option<CostModels>,
    #[n(19)]
    pub execution_costs: Option<ExUnitPrices>,
    #[n(20)]
    pub max_tx_ex_units: Option<ExUnits>,
    #[n(21)]
    pub max_block_ex_units: Option<ExUnits>,
    #[n(22)]
    pub max_value_size: Option<u64>,
    #[n(23)]
    pub collateral_percentage: Option<u64>,
    #[n(24)]
    pub max_collateral_inputs: Option<u64>,

    #[n(25)]
    pub pool_voting_thresholds: Option<PoolVotingThresholds>,
    #[n(26)]
    pub drep_voting_thresholds: Option<DRepVotingThresholds>,
    #[n(27)]
    pub min_committee_size: Option<u64>,
    #[n(28)]
    pub committee_term_limit: Option<Epoch>,
    #[n(29)]
    pub governance_action_validity_period: Option<Epoch>,
    #[n(30)]
    pub governance_action_deposit: Option<Coin>,
    #[n(31)]
    pub drep_deposit: Option<Coin>,
    #[n(32)]
    pub drep_inactivity_period: Option<Epoch>,
    #[n(33)]
    pub minfee_refscript_cost_per_byte: Option<UnitInterval>,
}

#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub struct Update {
    #[n(0)]
    pub proposed_protocol_parameter_updates: KeyValuePairs<Genesishash, ProtocolParamUpdate>,

    #[n(1)]
    pub epoch: Epoch,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct PoolVotingThresholds {
    pub motion_no_confidence: UnitInterval,
    pub committee_normal: UnitInterval,
    pub committee_no_confidence: UnitInterval,
    pub hard_fork_initiation: UnitInterval,
    pub security_voting_threshold: UnitInterval,
}

impl<'b, C> minicbor::Decode<'b, C> for PoolVotingThresholds {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        d.array()?;

        Ok(Self {
            motion_no_confidence: d.decode_with(ctx)?,
            committee_normal: d.decode_with(ctx)?,
            committee_no_confidence: d.decode_with(ctx)?,
            hard_fork_initiation: d.decode_with(ctx)?,
            security_voting_threshold: d.decode_with(ctx)?,
        })
    }
}

impl<C> minicbor::Encode<C> for PoolVotingThresholds {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.array(5)?;

        e.encode_with(&self.motion_no_confidence, ctx)?;
        e.encode_with(&self.committee_normal, ctx)?;
        e.encode_with(&self.committee_no_confidence, ctx)?;
        e.encode_with(&self.hard_fork_initiation, ctx)?;
        e.encode_with(&self.security_voting_threshold, ctx)?;

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct DRepVotingThresholds {
    pub motion_no_confidence: UnitInterval,
    pub committee_normal: UnitInterval,
    pub committee_no_confidence: UnitInterval,
    pub update_constitution: UnitInterval,
    pub hard_fork_initiation: UnitInterval,
    pub pp_network_group: UnitInterval,
    pub pp_economic_group: UnitInterval,
    pub pp_technical_group: UnitInterval,
    pub pp_governance_group: UnitInterval,
    pub treasury_withdrawal: UnitInterval,
}

impl<'b, C> minicbor::Decode<'b, C> for DRepVotingThresholds {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        d.array()?;

        Ok(Self {
            motion_no_confidence: d.decode_with(ctx)?,
            committee_normal: d.decode_with(ctx)?,
            committee_no_confidence: d.decode_with(ctx)?,
            update_constitution: d.decode_with(ctx)?,
            hard_fork_initiation: d.decode_with(ctx)?,
            pp_network_group: d.decode_with(ctx)?,
            pp_economic_group: d.decode_with(ctx)?,
            pp_technical_group: d.decode_with(ctx)?,
            pp_governance_group: d.decode_with(ctx)?,
            treasury_withdrawal: d.decode_with(ctx)?,
        })
    }
}

impl<C> minicbor::Encode<C> for DRepVotingThresholds {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.array(10)?;

        e.encode_with(&self.motion_no_confidence, ctx)?;
        e.encode_with(&self.committee_normal, ctx)?;
        e.encode_with(&self.committee_no_confidence, ctx)?;
        e.encode_with(&self.update_constitution, ctx)?;
        e.encode_with(&self.hard_fork_initiation, ctx)?;
        e.encode_with(&self.pp_network_group, ctx)?;
        e.encode_with(&self.pp_economic_group, ctx)?;
        e.encode_with(&self.pp_technical_group, ctx)?;
        e.encode_with(&self.pp_governance_group, ctx)?;
        e.encode_with(&self.treasury_withdrawal, ctx)?;

        Ok(())
    }
}

#[derive(Encode, Debug, PartialEq, Clone)]
#[cbor(map)]
pub struct PseudoTransactionBody<T1> {
    #[n(0)]
    pub inputs: Set<TransactionInput>,

    #[n(1)]
    pub outputs: Vec<T1>,

    #[n(2)]
    pub fee: Coin,

    #[n(3)]
    pub ttl: Option<u64>,

    #[n(4)]
    pub certificates: Option<NonEmptySet<Certificate>>,

    #[n(5)]
    pub withdrawals: Option<NonEmptyKeyValuePairs<RewardAccount, Coin>>,

    #[n(7)]
    pub auxiliary_data_hash: Option<Bytes>,

    #[n(8)]
    pub validity_interval_start: Option<u64>,

    #[n(9)]
    pub mint: Option<Multiasset<NonZeroInt>>,

    #[n(11)]
    pub script_data_hash: Option<Hash<32>>,

    #[n(13)]
    pub collateral: Option<NonEmptySet<TransactionInput>>,

    #[n(14)]
    pub required_signers: Option<RequiredSigners>,

    #[n(15)]
    pub network_id: Option<NetworkId>,

    #[n(16)]
    pub collateral_return: Option<T1>,

    #[n(17)]
    pub total_collateral: Option<Coin>,

    #[n(18)]
    pub reference_inputs: Option<NonEmptySet<TransactionInput>>,

    // -- NEW IN CONWAY
    #[n(19)]
    pub voting_procedures: Option<VotingProcedures>,

    #[n(20)]
    pub proposal_procedures: Option<NonEmptySet<ProposalProcedure>>,

    #[n(21)]
    pub treasury_value: Option<Coin>,

    #[n(22)]
    pub donation: Option<PositiveCoin>,
}

pub type TransactionBody = PseudoTransactionBody<TransactionOutput>;

#[derive(Clone, Debug)]
enum TxBodyField<T1> {
    Inputs(Set<TransactionInput>),
    Outputs(Vec<T1>),
    Fee(Coin),
    Ttl(Option<u64>),
    Certificates(Option<NonEmptySet<Certificate>>),
    Withdrawals(Option<NonEmptyKeyValuePairs<RewardAccount, Coin>>),
    AuxiliaryDataHash(Option<Bytes>),
    ValidityIntervalStart(Option<u64>),
    Mint(Option<Multiasset<NonZeroInt>>),
    ScriptDataHash(Option<Hash<32>>),
    Collateral(Option<NonEmptySet<TransactionInput>>),
    RequiredSigners(Option<RequiredSigners>),
    NetworkId(Option<NetworkId>),
    CollateralReturn(Option<T1>),
    TotalCollateral(Option<Coin>),
    ReferenceInputs(Option<NonEmptySet<TransactionInput>>),
    VotingProcedures(Option<VotingProcedures>),
    ProposalProcedures(Option<NonEmptySet<ProposalProcedure>>),
    TreasuryValue(Option<Coin>),
    Donation(Option<PositiveCoin>),
}

fn decode_tx_body_field<'b, T1, Ctx>(d: &mut minicbor::Decoder<'b>, k: u64, ctx: &mut Ctx) -> Result<TxBodyField<T1>, minicbor::decode::Error>
where
    Ctx: ValidationContext,
    T1: minicbor::Decode<'b, Ctx>
{
    match k {
        0 => {
            let inputs = d.decode_with(ctx)?;
            Ok(TxBodyField::Inputs(inputs))
        },
        1 => {
            let outputs = d.decode_with(ctx)?;
            Ok(TxBodyField::Outputs(outputs))
        },
        2 => {
            let coin = d.decode_with(ctx)?;
            Ok(TxBodyField::Fee(coin))
        },
        3 => {
            let ttl = d.decode_with(ctx)?;
            Ok(TxBodyField::Ttl(ttl))
        },
        4 => {
            let certificates = d.decode_with(ctx)?;
            Ok(TxBodyField::Certificates(certificates))
        },
        5 => {
            let withdrawals = d.decode_with(ctx)?;
            Ok(TxBodyField::Withdrawals(withdrawals))
        }
        7 => {
            let auxiliary_data_hash= d.decode_with(ctx)?;
            Ok(TxBodyField::AuxiliaryDataHash(auxiliary_data_hash))
        }
        8 => {
            let validity_interval_start = d.decode_with(ctx)?;
            Ok(TxBodyField::ValidityIntervalStart(validity_interval_start))
        }
        9 => {
            let mint = d.decode_with(ctx)?;
            Ok(TxBodyField::Mint(mint))
        }
        11 => {
            let script_data_hash = d.decode_with(ctx)?;
            Ok(TxBodyField::ScriptDataHash(script_data_hash))
        }
        13 => {
            let collateral = d.decode_with(ctx)?;
            Ok(TxBodyField::Collateral(collateral))
        }
        14 => {
            let required_signers = d.decode_with(ctx)?;
            Ok(TxBodyField::RequiredSigners(required_signers))
        }
        15 => {
            let network_id = d.decode_with(ctx)?;
            Ok(TxBodyField::NetworkId(network_id))
        }
        16 => {
            let collateral_return = d.decode_with(ctx)?;
            Ok(TxBodyField::CollateralReturn(collateral_return))
        }
        17 => {
            let total_collateral = d.decode_with(ctx)?;
            Ok(TxBodyField::TotalCollateral(total_collateral))
        }
        18 => {
            let reference_inputs = d.decode_with(ctx)?;
            Ok(TxBodyField::ReferenceInputs(reference_inputs))
        }
        19 => {
            let voting_procedures = d.decode_with(ctx)?;
            Ok(TxBodyField::VotingProcedures(voting_procedures))
        }
        20 => {
            let proposal_procedures = d.decode_with(ctx)?;
            Ok(TxBodyField::ProposalProcedures(proposal_procedures))
        }
        21 => {
            let treasury_value = d.decode_with(ctx)?;
            Ok(TxBodyField::TreasuryValue(treasury_value))
        }
        22 => {
            let donation = d.decode_with(ctx)?;
            Ok(TxBodyField::Donation(donation))
        }
        k => Err(minicbor::decode::Error::message(format!("Unknown txbody field key {}", k)))
    }
}

struct TxBodyFields<T1> {
    entries: BTreeMap<u64, Vec<TxBodyField<T1>>>,
}

impl <'b, T1, Ctx> minicbor::Decode<'b, Ctx> for TxBodyFields<T1>
where
    T1: Clone + minicbor::Decode<'b, Ctx>,
    Ctx: ValidationContext
{
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut Ctx) -> Result<Self, minicbor::decode::Error> {
        let mut entries = BTreeMap::new();
        let map_size = d.map()?;
        match map_size {
            None => {
                loop {
                    let ty = d.datatype()?;
                    if ty == Type::Break {
                        d.skip()?;
                        break;
                    }
                    let k = d.u64()?;
                    let v = decode_tx_body_field(d, k, ctx)?;
                    entries.entry(k).and_modify(|ar: &mut Vec<TxBodyField<T1>>| ar.push(v.clone())).or_insert(vec![v]);
                }
            },
            Some(n) => {
                for _ in 0..n {
                    let k = d.u64()?;
                    let v = decode_tx_body_field(d, k, ctx)?;
                    entries.entry(k).and_modify(|ar: &mut Vec<TxBodyField<T1>>| ar.push(v.clone())).or_insert(vec![v]);
                }
            }
        }
        Ok(TxBodyFields {
            entries
        })
    }
}

fn make_basic_tx_body<T1>(inputs: Set<TransactionInput>, outputs: Vec<T1>, fee: Coin) -> PseudoTransactionBody<T1> {
    PseudoTransactionBody {
        inputs,
        outputs,
        fee,
        ttl: None,
        certificates: None,
        withdrawals: None,
        auxiliary_data_hash: None,
        validity_interval_start: None,
        mint: None,
        script_data_hash: None,
        collateral: None,
        required_signers: None,
        network_id: None,
        collateral_return: None,
        total_collateral: None,
        reference_inputs: None,
        voting_procedures: None,
        proposal_procedures: None,
        treasury_value: None,
        donation: None,
    }
}

fn set_tx_body_field<'a, T1>(txbody: &mut PseudoTransactionBody<T1>, index: u64, field: TxBodyField<T1>) -> Result<(), String>
where
    T1: Debug 
{
    match (index, field) {
        (0, TxBodyField::Inputs(i)) => {
            txbody.inputs = i;
        },
        (1, TxBodyField::Outputs(o)) => {
            txbody.outputs = o;
        },
        (2, TxBodyField::Fee(f)) => {
            txbody.fee = f;
        }
        (3, TxBodyField::Ttl(t)) => {
            txbody.ttl = t;
        }
        (4, TxBodyField::Certificates(c)) => {
            txbody.certificates = c;
        }
        (5, TxBodyField::Withdrawals(w)) => {
            txbody.withdrawals = w;
        }
        (7, TxBodyField::AuxiliaryDataHash(a)) => {
            txbody.auxiliary_data_hash = a;
        }
        (8, TxBodyField::ValidityIntervalStart(v)) => {
            txbody.validity_interval_start = v;
        }
        (9, TxBodyField::Mint(m)) => {
            txbody.mint = m;
        }
        (11, TxBodyField::ScriptDataHash(s)) => {
            txbody.script_data_hash = s;
        }
        (13, TxBodyField::Collateral(c)) => {
            txbody.collateral = c;
        }
        (14, TxBodyField::RequiredSigners(r)) => {
            txbody.required_signers = r;
        }
        (15, TxBodyField::NetworkId(n)) => {
            txbody.network_id = n;
        }
        (16, TxBodyField::CollateralReturn(c)) => {
            txbody.collateral_return = c;
        }
        (17, TxBodyField::TotalCollateral(t)) => {
            txbody.total_collateral = t;
        }
        (18, TxBodyField::ReferenceInputs(r)) => {
            txbody.reference_inputs = r;
        }
        (19, TxBodyField::VotingProcedures(v)) => {
            txbody.voting_procedures = v;
        }
        (20, TxBodyField::ProposalProcedures(p)) => {
            txbody.proposal_procedures = p;
        }
        (21, TxBodyField::TreasuryValue(t)) => {
            txbody.treasury_value = t;
        }
        (22, TxBodyField::Donation(d)) => {
            txbody.donation = d;
        }
        (ix, f) => {
            return Err(format!("Wrong index {} for txbody field {:?}", ix, f))
        }
    }
    Ok(())
}

impl <'b, T1, Ctx> minicbor::Decode<'b, Ctx> for PseudoTransactionBody<T1>
where
    T1: Clone + Debug + minicbor::Decode<'b, Ctx>,
    Ctx: ValidationContext
{
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut Ctx) -> Result<Self, minicbor::decode::Error> {
        let fields: TxBodyFields<T1> = d.decode_with(ctx)?;
        let entries = fields.entries;
        let inputs = entries.get(&0).and_then(|v| v.first());
        let outputs = entries.get(&1).and_then(|v| v.first());
        let fee = entries.get(&2).and_then(|v| v.first());
        let mut tx_body = match (inputs, outputs, fee) {
            (Some(TxBodyField::Inputs(inputs)), Some(TxBodyField::Outputs(outputs)), Some(TxBodyField::Fee(fee))) => {
                make_basic_tx_body(inputs.clone(), outputs.clone(), *fee)
            },
            _ => {
                return Err(minicbor::decode::Error::message("inputs, outputs, and fee fields are required"))
            },
        };
        for (key, val) in entries {
            if val.len() > 1 {
                ctx.push_error(format!("duplicate txbody entries for key {}", key))?;
            }
            match val.first() {
                Some(first) => {
                    let result = set_tx_body_field(&mut tx_body, key, first.clone());
                    if let Err(e) = result {
                        return Err(minicbor::decode::Error::message(
                                format!("could not set txbody field: {}", e)
                        ));
                    }
                },
                None => {
                    // This is impossible because we always initialize TxBodyFields entries with
                    // singleton arrays. Could maybe use a NonEmpty Vec type to eliminate this
                    // branch
                    return Err(minicbor::decode::Error::message("TxBodyFields entry was empty"))
                }
            }
        }
        Ok(tx_body)
    }
}

//#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
//pub struct NonEmptyMap<K, V> {
//    #[serde(bound(deserialize = "K: Deserialize<'de> + Ord, V: Deserialize<'de>"))]
//    map: BTreeMap<K, V>
//}
//
//impl<K, V, C> minicbor::Encode<C> for NonEmptyMap<K, V>
//where
//    K: minicbor::Encode<C> + Ord,
//    V: minicbor::Encode<C>
//{
//    fn encode<W: minicbor::encode::Write>(
//        &self,
//        e: &mut minicbor::Encoder<W>,
//        ctx: &mut C,
//    ) -> Result<(), minicbor::encode::Error<W::Error>> {
//        e.encode_with(&self.map, ctx)?;
//        Ok(())
//    }
//}
//
//impl <'b, Ctx, K, V> minicbor::Decode<'b, Ctx> for NonEmptyMap<K, V>
//where
//    K: minicbor::Decode<'b, Ctx> + Eq + Ord,
//    V: minicbor::Decode<'b, Ctx>,
//    Ctx: ValidationContext
//{
//    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut Ctx) -> Result<Self, minicbor::decode::Error> {
//        let map: BTreeMap<K, V> = d.decode_with(ctx)?;
//        if map.is_empty() {
//            ctx.push_error("map must not be empty".to_string())?;
//        }
//        Ok(NonEmptyMap { map })
//    }
//}
//
//impl<K, V> std::ops::Deref for NonEmptyMap<K, V> {
//    type Target = BTreeMap<K, V>;
//
//    fn deref(&self) -> &Self::Target {
//        &self.map
//    }
//}


//#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
//pub struct NonEmptyMultiasset<T: Clone> {
//    asset: Multiasset<T>
//}
//
//impl<C, T> minicbor::Encode<C> for NonEmptyMultiasset<T>
//where T: Clone + minicbor::Encode<C>
//{
//    fn encode<W: minicbor::encode::Write>(
//        &self,
//        e: &mut minicbor::Encoder<W>,
//        ctx: &mut C,
//    ) -> Result<(), minicbor::encode::Error<W::Error>> {
//        e.encode_with(&self.asset, ctx)?;
//        Ok(())
//    }
//}
//
//impl <'b, Ctx, T> minicbor::Decode<'b, Ctx> for NonEmptyMultiasset<T>
//where
//    T: Clone + minicbor::Decode<'b, Ctx>,
//    Ctx: ValidationContext
//{
//    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut Ctx) -> Result<Self, minicbor::decode::Error> {
//        let asset: Multiasset<T> = d.decode_with(ctx)?;
//        if let NonEmptyKeyValuePairs::Def(ref v) = asset && v.is_empty() {
//            ctx.push_error("multiasset must not be empty".to_string())?;
//        } else if let NonEmptyKeyValuePairs::Def(ref v) = asset && v.is_empty() {
//            ctx.push_error("multiasset must not be empty".to_string())?;
//        }
//        Ok(NonEmptyMultiasset { asset })
//    }
//}
//
//impl<A> std::ops::Deref for NonEmptyMultiasset<A> {
//    type Target = BTreeMap<PolicyId, BTreeMap<AssetName, A>>;
//
//    fn deref(&self) -> &Self::Target {
//        &self.asset.0
//    }
//}
//
//impl<A> NonEmptyMultiasset<A> where A: Clone {
//    pub fn from_multiasset(ma: Multiasset<A>) -> Option<Self> {
//        if let NonEmptyKeyValuePairs::Def(ref v) = ma && v.is_empty() {
//            None
//        } else if let NonEmptyKeyValuePairs::Indef(ref v) = ma && v.is_empty() {
//            None
//        } else {
//            Some(NonEmptyMultiasset {
//                asset: ma,
//            })
//        }
//    }
//
//    pub fn to_multiasset(self) -> Multiasset<A> {
//        self.asset
//    }
//}

pub type MintedTransactionBody<'a> = PseudoTransactionBody<MintedTransactionOutput<'a>>;

impl<'a> From<MintedTransactionBody<'a>> for TransactionBody {
    fn from(value: MintedTransactionBody<'a>) -> Self {
        Self {
            inputs: value.inputs,
            outputs: value.outputs.into_iter().map(|x| x.into()).collect(),
            fee: value.fee,
            ttl: value.ttl,
            certificates: value.certificates,
            withdrawals: value.withdrawals,
            auxiliary_data_hash: value.auxiliary_data_hash,
            validity_interval_start: value.validity_interval_start,
            mint: value.mint,
            script_data_hash: value.script_data_hash,
            collateral: value.collateral,
            required_signers: value.required_signers,
            network_id: value.network_id,
            collateral_return: value.collateral_return.map(|x| x.into()),
            total_collateral: value.total_collateral,
            reference_inputs: value.reference_inputs,
            voting_procedures: value.voting_procedures,
            proposal_procedures: value.proposal_procedures,
            treasury_value: value.treasury_value,
            donation: value.donation,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum Vote {
    No,
    Yes,
    Abstain,
}

impl<'b, C> minicbor::Decode<'b, C> for Vote {
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        _ctx: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        match d.u8()? {
            0 => Ok(Self::No),
            1 => Ok(Self::Yes),
            2 => Ok(Self::Abstain),
            _ => Err(minicbor::decode::Error::message(
                "invalid number for Vote kind",
            )),
        }
    }
}

impl<C> minicbor::Encode<C> for Vote {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match &self {
            Self::No => e.u8(0)?,
            Self::Yes => e.u8(1)?,
            Self::Abstain => e.u8(2)?,
        };

        Ok(())
    }
}

pub type VotingProcedures =
    NonEmptyKeyValuePairs<Voter, NonEmptyKeyValuePairs<GovActionId, VotingProcedure>>;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct VotingProcedure {
    pub vote: Vote,
    pub anchor: Nullable<Anchor>,
}

impl<'b, C> minicbor::Decode<'b, C> for VotingProcedure {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        d.array()?;

        Ok(Self {
            vote: d.decode_with(ctx)?,
            anchor: d.decode_with(ctx)?,
        })
    }
}

impl<C> minicbor::Encode<C> for VotingProcedure {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.array(2)?;

        e.encode_with(&self.vote, ctx)?;
        e.encode_with(&self.anchor, ctx)?;

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct ProposalProcedure {
    pub deposit: Coin,
    pub reward_account: RewardAccount,
    pub gov_action: GovAction,
    pub anchor: Anchor,
}

impl<'b, C> minicbor::Decode<'b, C> for ProposalProcedure {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        d.array()?;

        Ok(Self {
            deposit: d.decode_with(ctx)?,
            reward_account: d.decode_with(ctx)?,
            gov_action: d.decode_with(ctx)?,
            anchor: d.decode_with(ctx)?,
        })
    }
}

impl<C> minicbor::Encode<C> for ProposalProcedure {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.array(4)?;

        e.encode_with(self.deposit, ctx)?;
        e.encode_with(&self.reward_account, ctx)?;
        e.encode_with(&self.gov_action, ctx)?;
        e.encode_with(&self.anchor, ctx)?;

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum GovAction {
    ParameterChange(
        Nullable<GovActionId>,
        Box<ProtocolParamUpdate>,
        Nullable<ScriptHash>,
    ),
    HardForkInitiation(Nullable<GovActionId>, ProtocolVersion),
    TreasuryWithdrawals(KeyValuePairs<RewardAccount, Coin>, Nullable<ScriptHash>),
    NoConfidence(Nullable<GovActionId>),
    UpdateCommittee(
        Nullable<GovActionId>,
        Set<CommitteeColdCredential>,
        KeyValuePairs<CommitteeColdCredential, Epoch>,
        UnitInterval,
    ),
    NewConstitution(Nullable<GovActionId>, Constitution),
    Information,
}

impl<'b, C> minicbor::decode::Decode<'b, C> for GovAction {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        d.array()?;
        let variant = d.u16()?;

        match variant {
            0 => {
                let a = d.decode_with(ctx)?;
                let b = d.decode_with(ctx)?;
                let c = d.decode_with(ctx)?;
                Ok(GovAction::ParameterChange(a, b, c))
            }
            1 => {
                let a = d.decode_with(ctx)?;
                let b = d.decode_with(ctx)?;
                Ok(GovAction::HardForkInitiation(a, b))
            }
            2 => {
                let a = d.decode_with(ctx)?;
                let b = d.decode_with(ctx)?;
                Ok(GovAction::TreasuryWithdrawals(a, b))
            }
            3 => {
                let a = d.decode_with(ctx)?;
                Ok(GovAction::NoConfidence(a))
            }
            4 => {
                let a = d.decode_with(ctx)?;
                let b = d.decode_with(ctx)?;
                let c = d.decode_with(ctx)?;
                let d = d.decode_with(ctx)?;
                Ok(GovAction::UpdateCommittee(a, b, c, d))
            }
            5 => {
                let a = d.decode_with(ctx)?;
                let b = d.decode_with(ctx)?;
                Ok(GovAction::NewConstitution(a, b))
            }
            6 => Ok(GovAction::Information),
            _ => Err(minicbor::decode::Error::message(
                "unknown variant id for certificate",
            )),
        }
    }
}

impl<C> minicbor::encode::Encode<C> for GovAction {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            GovAction::ParameterChange(a, b, c) => {
                e.array(4)?;
                e.u16(0)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
                e.encode_with(c, ctx)?;
            }
            GovAction::HardForkInitiation(a, b) => {
                e.array(3)?;
                e.u16(1)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
            }
            GovAction::TreasuryWithdrawals(a, b) => {
                e.array(3)?;
                e.u16(2)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
            }
            GovAction::NoConfidence(a) => {
                e.array(2)?;
                e.u16(3)?;
                e.encode_with(a, ctx)?;
            }
            GovAction::UpdateCommittee(a, b, c, d) => {
                e.array(5)?;
                e.u16(4)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
                e.encode_with(c, ctx)?;
                e.encode_with(d, ctx)?;
            }
            GovAction::NewConstitution(a, b) => {
                e.array(3)?;
                e.u16(5)?;
                e.encode_with(a, ctx)?;
                e.encode_with(b, ctx)?;
            }
            // TODO: CDDL says just "6", not group/array "(6)"?
            GovAction::Information => {
                e.array(1)?;
                e.u16(6)?;
            }
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct Constitution {
    pub anchor: Anchor,
    pub guardrail_script: Nullable<ScriptHash>,
}

impl<'b, C> minicbor::Decode<'b, C> for Constitution {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        d.array()?;

        Ok(Self {
            anchor: d.decode_with(ctx)?,
            guardrail_script: d.decode_with(ctx)?,
        })
    }
}

impl<C> minicbor::Encode<C> for Constitution {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.array(2)?;

        e.encode_with(&self.anchor, ctx)?;
        e.encode_with(&self.guardrail_script, ctx)?;

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, PartialOrd, Eq, Ord, Clone)]
pub enum Voter {
    ConstitutionalCommitteeScript(ScriptHash),
    ConstitutionalCommitteeKey(AddrKeyhash),
    DRepScript(ScriptHash),
    DRepKey(AddrKeyhash),
    StakePoolKey(AddrKeyhash),
}

impl<'b, C> minicbor::decode::Decode<'b, C> for Voter {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        d.array()?;
        let variant = d.u16()?;

        match variant {
            0 => Ok(Voter::ConstitutionalCommitteeKey(d.decode_with(ctx)?)),
            1 => Ok(Voter::ConstitutionalCommitteeScript(d.decode_with(ctx)?)),
            2 => Ok(Voter::DRepKey(d.decode_with(ctx)?)),
            3 => Ok(Voter::DRepScript(d.decode_with(ctx)?)),
            4 => Ok(Voter::StakePoolKey(d.decode_with(ctx)?)),
            _ => Err(minicbor::decode::Error::message(
                "invalid variant id for DRep",
            )),
        }
    }
}

impl<C> minicbor::encode::Encode<C> for Voter {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.array(2)?;

        match self {
            Voter::ConstitutionalCommitteeKey(h) => {
                e.encode_with(0, ctx)?;
                e.encode_with(h, ctx)?;

                Ok(())
            }
            Voter::ConstitutionalCommitteeScript(h) => {
                e.encode_with(1, ctx)?;
                e.encode_with(h, ctx)?;

                Ok(())
            }
            Voter::DRepKey(h) => {
                e.encode_with(2, ctx)?;
                e.encode_with(h, ctx)?;

                Ok(())
            }
            Voter::DRepScript(h) => {
                e.encode_with(3, ctx)?;
                e.encode_with(h, ctx)?;

                Ok(())
            }
            Voter::StakePoolKey(h) => {
                e.encode_with(4, ctx)?;
                e.encode_with(h, ctx)?;

                Ok(())
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, PartialOrd, Eq, Ord, Clone)]
pub struct Anchor {
    pub url: String,
    pub content_hash: Hash<32>,
}

impl<'b, C> minicbor::Decode<'b, C> for Anchor {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        d.array()?;

        Ok(Self {
            url: d.decode_with(ctx)?,
            content_hash: d.decode_with(ctx)?,
        })
    }
}

impl<C> minicbor::Encode<C> for Anchor {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.array(2)?;

        e.encode_with(&self.url, ctx)?;
        e.encode_with(self.content_hash, ctx)?;

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub struct GovActionId {
    pub transaction_id: Hash<32>,
    pub action_index: u32,
}

impl<'b, C> minicbor::Decode<'b, C> for GovActionId {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        d.array()?;

        Ok(Self {
            transaction_id: d.decode_with(ctx)?,
            action_index: d.decode_with(ctx)?,
        })
    }
}

impl<C> minicbor::Encode<C> for GovActionId {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.array(2)?;

        e.encode_with(self.transaction_id, ctx)?;
        e.encode_with(self.action_index, ctx)?;

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PseudoTransactionOutput<T> {
    Legacy(LegacyTransactionOutput),
    PostAlonzo(T),
}

impl<'b, C, T> minicbor::Decode<'b, C> for PseudoTransactionOutput<T>
where
    T: minicbor::Decode<'b, C>,
{
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        match d.datatype()? {
            minicbor::data::Type::Array | minicbor::data::Type::ArrayIndef => {
                Ok(PseudoTransactionOutput::Legacy(d.decode_with(ctx)?))
            }
            minicbor::data::Type::Map | minicbor::data::Type::MapIndef => {
                Ok(PseudoTransactionOutput::PostAlonzo(d.decode_with(ctx)?))
            }
            _ => Err(minicbor::decode::Error::message(
                "invalid type for transaction output struct",
            )),
        }
    }
}

impl<C, T> minicbor::Encode<C> for PseudoTransactionOutput<T>
where
    T: minicbor::Encode<C>,
{
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            PseudoTransactionOutput::Legacy(x) => x.encode(e, ctx),
            PseudoTransactionOutput::PostAlonzo(x) => x.encode(e, ctx),
        }
    }
}

pub type PostAlonzoTransactionOutput =
    crate::babbage::PseudoPostAlonzoTransactionOutput<Value, DatumOption, ScriptRef>;

pub type TransactionOutput = PseudoTransactionOutput<PostAlonzoTransactionOutput>;

pub type MintedTransactionOutput<'b> =
    PseudoTransactionOutput<MintedPostAlonzoTransactionOutput<'b>>;

impl<'b> From<MintedTransactionOutput<'b>> for TransactionOutput {
    fn from(value: MintedTransactionOutput<'b>) -> Self {
        match value {
            PseudoTransactionOutput::Legacy(x) => Self::Legacy(x),
            PseudoTransactionOutput::PostAlonzo(x) => Self::PostAlonzo(x.into()),
        }
    }
}

pub type MintedPostAlonzoTransactionOutput<'b> = crate::babbage::PseudoPostAlonzoTransactionOutput<
    Value,
    MintedDatumOption<'b>,
    MintedScriptRef<'b>,
>;

impl<'b> From<MintedPostAlonzoTransactionOutput<'b>> for PostAlonzoTransactionOutput {
    fn from(value: MintedPostAlonzoTransactionOutput<'b>) -> Self {
        Self {
            address: value.address,
            value: value.value,
            datum_option: value.datum_option.map(|x| x.into()),
            script_ref: value.script_ref.map(|x| CborWrap(x.unwrap().into())),
        }
    }
}

pub use crate::alonzo::VKeyWitness;

pub use crate::alonzo::NativeScript;

#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub struct ExUnitPrices {
    #[n(0)]
    pub mem_price: RationalNumber,

    #[n(1)]
    pub step_price: RationalNumber,
}

#[derive(
    Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy,
)]
#[cbor(index_only)]
pub enum RedeemerTag {
    #[n(0)]
    Spend,
    #[n(1)]
    Mint,
    #[n(2)]
    Cert,
    #[n(3)]
    Reward,
    #[n(4)]
    Vote,
    #[n(5)]
    Propose,
}

#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub struct Redeemer {
    #[n(0)]
    pub tag: RedeemerTag,

    #[n(1)]
    pub index: u32,

    #[n(2)]
    pub data: PlutusData,

    #[n(3)]
    pub ex_units: ExUnits,
}

#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct RedeemersKey {
    #[n(0)]
    pub tag: RedeemerTag,
    #[n(1)]
    pub index: u32,
}

#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub struct RedeemersValue {
    #[n(0)]
    pub data: PlutusData,
    #[n(1)]
    pub ex_units: ExUnits,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum Redeemers {
    List(MaybeIndefArray<Redeemer>),
    Map(NonEmptyKeyValuePairs<RedeemersKey, RedeemersValue>),
}

impl From<NonEmptyKeyValuePairs<RedeemersKey, RedeemersValue>> for Redeemers {
    fn from(value: NonEmptyKeyValuePairs<RedeemersKey, RedeemersValue>) -> Self {
        Redeemers::Map(value)
    }
}

impl<'b, C> minicbor::Decode<'b, C> for Redeemers {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        match d.datatype()? {
            minicbor::data::Type::Array | minicbor::data::Type::ArrayIndef => {
                Ok(Self::List(d.decode_with(ctx)?))
            }
            minicbor::data::Type::Map | minicbor::data::Type::MapIndef => {
                Ok(Self::Map(d.decode_with(ctx)?))
            }
            _ => Err(minicbor::decode::Error::message(
                "invalid type for redeemers struct",
            )),
        }
    }
}

impl<C> minicbor::Encode<C> for Redeemers {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Self::List(x) => e.encode_with(x, ctx)?,
            Self::Map(x) => e.encode_with(x, ctx)?,
        };

        Ok(())
    }
}

pub use crate::alonzo::BootstrapWitness;

#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Clone)]
#[cbor(map)]
pub struct WitnessSet {
    #[n(0)]
    pub vkeywitness: Option<NonEmptySet<VKeyWitness>>,

    #[n(1)]
    pub native_script: Option<NonEmptySet<NativeScript>>,

    #[n(2)]
    pub bootstrap_witness: Option<NonEmptySet<BootstrapWitness>>,

    #[n(3)]
    pub plutus_v1_script: Option<NonEmptySet<PlutusScript<1>>>,

    #[n(4)]
    pub plutus_data: Option<NonEmptySet<PlutusData>>,

    #[n(5)]
    pub redeemer: Option<Redeemers>,

    #[n(6)]
    pub plutus_v2_script: Option<NonEmptySet<PlutusScript<2>>>,

    #[n(7)]
    pub plutus_v3_script: Option<NonEmptySet<PlutusScript<3>>>,
}

#[derive(Encode, Decode, Debug, PartialEq, Clone)]
#[cbor(map)]
pub struct MintedWitnessSet<'b> {
    #[n(0)]
    pub vkeywitness: Option<NonEmptySet<VKeyWitness>>,

    #[n(1)]
    pub native_script: Option<NonEmptySet<KeepRaw<'b, NativeScript>>>,

    #[n(2)]
    pub bootstrap_witness: Option<NonEmptySet<BootstrapWitness>>,

    #[n(3)]
    pub plutus_v1_script: Option<NonEmptySet<PlutusScript<1>>>,

    #[b(4)]
    pub plutus_data: Option<NonEmptySet<KeepRaw<'b, PlutusData>>>,

    #[n(5)]
    pub redeemer: Option<KeepRaw<'b, Redeemers>>,

    #[n(6)]
    pub plutus_v2_script: Option<NonEmptySet<PlutusScript<2>>>,

    #[n(7)]
    pub plutus_v3_script: Option<NonEmptySet<PlutusScript<3>>>,
}

impl<'b> From<MintedWitnessSet<'b>> for WitnessSet {
    fn from(x: MintedWitnessSet<'b>) -> Self {
        WitnessSet {
            vkeywitness: x.vkeywitness,
            native_script: x.native_script.map(Into::into),
            bootstrap_witness: x.bootstrap_witness,
            plutus_v1_script: x.plutus_v1_script,
            plutus_data: x.plutus_data.map(Into::into),
            redeemer: x.redeemer.map(|x| x.unwrap()),
            plutus_v2_script: x.plutus_v2_script,
            plutus_v3_script: x.plutus_v3_script,
        }
    }
}

#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Clone)]
#[cbor(map)]
pub struct PostAlonzoAuxiliaryData {
    #[n(0)]
    pub metadata: Option<Metadata>,

    #[n(1)]
    pub native_scripts: Option<Vec<NativeScript>>,

    #[n(2)]
    pub plutus_v1_scripts: Option<Vec<PlutusScript<1>>>,

    #[n(3)]
    pub plutus_v2_scripts: Option<Vec<PlutusScript<2>>>,

    #[n(4)]
    pub plutus_v3_scripts: Option<Vec<PlutusScript<3>>>,
}

pub use crate::babbage::DatumHash;

pub use crate::babbage::PseudoDatumOption;

pub use crate::babbage::DatumOption;

pub use crate::babbage::MintedDatumOption;

#[deprecated(since = "0.31.0", note = "use `PlutusScript<1>` instead")]
pub type PlutusV1Script = PlutusScript<1>;

#[deprecated(since = "0.31.0", note = "use `PlutusScript<2>` instead")]
pub type PlutusV2Script = PlutusScript<2>;

#[deprecated(since = "0.31.0", note = "use `PlutusScript<3>` instead")]
pub type PlutusV3Script = PlutusScript<3>;

// script = [ 0, native_script // 1, plutus_v1_script // 2, plutus_v2_script ]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PseudoScript<T1> {
    NativeScript(T1),
    PlutusV1Script(PlutusScript<1>),
    PlutusV2Script(PlutusScript<2>),
    PlutusV3Script(PlutusScript<3>),
}

// script_ref = #6.24(bytes .cbor script)
pub type ScriptRef = PseudoScript<NativeScript>;

pub type MintedScriptRef<'b> = PseudoScript<KeepRaw<'b, NativeScript>>;

impl<'b> From<MintedScriptRef<'b>> for ScriptRef {
    fn from(value: MintedScriptRef<'b>) -> Self {
        match value {
            PseudoScript::NativeScript(x) => Self::NativeScript(x.unwrap()),
            PseudoScript::PlutusV1Script(x) => Self::PlutusV1Script(x),
            PseudoScript::PlutusV2Script(x) => Self::PlutusV2Script(x),
            PseudoScript::PlutusV3Script(x) => Self::PlutusV3Script(x),
        }
    }
}

// TODO: Remove in favour of multierascriptref
impl<'b> From<babbage::MintedScriptRef<'b>> for MintedScriptRef<'b> {
    fn from(value: babbage::MintedScriptRef<'b>) -> Self {
        match value {
            babbage::MintedScriptRef::NativeScript(x) => Self::NativeScript(x),
            babbage::MintedScriptRef::PlutusV1Script(x) => Self::PlutusV1Script(x),
            babbage::MintedScriptRef::PlutusV2Script(x) => Self::PlutusV2Script(x),
        }
    }
}

impl<'b, C, T> minicbor::Decode<'b, C> for PseudoScript<T>
where
    T: minicbor::Decode<'b, ()>,
{
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        _ctx: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        d.array()?;

        match d.u8()? {
            0 => Ok(Self::NativeScript(d.decode()?)),
            1 => Ok(Self::PlutusV1Script(d.decode()?)),
            2 => Ok(Self::PlutusV2Script(d.decode()?)),
            3 => Ok(Self::PlutusV3Script(d.decode()?)),
            x => Err(minicbor::decode::Error::message(format!(
                "invalid variant for script enum: {}",
                x
            ))),
        }
    }
}

impl<C, T> minicbor::Encode<C> for PseudoScript<T>
where
    T: minicbor::Encode<C>,
{
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Self::NativeScript(x) => e.encode_with((0, x), ctx)?,
            Self::PlutusV1Script(x) => e.encode_with((1, x), ctx)?,
            Self::PlutusV2Script(x) => e.encode_with((2, x), ctx)?,
            Self::PlutusV3Script(x) => e.encode_with((3, x), ctx)?,
        };

        Ok(())
    }
}

// FIXME: re-exporting here means it does not use the above PostAlonzoAuxiliaryData; instead, it
// uses the one defined in the alonzo module, which only supports plutus V1 scripts
//
// Same problem exists in the babbage module
//
// should probably take a type parameter for the post-alonzo variant or just define a whole
// separate type here and in babbage
pub use crate::alonzo::AuxiliaryData;

use crate::babbage::MintedHeader;

#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Clone)]
pub struct PseudoBlock<T1, T2, T3, T4>
where
    T4: std::clone::Clone,
{
    #[n(0)]
    pub header: T1,

    #[b(1)]
    pub transaction_bodies: MaybeIndefArray<T2>,

    #[n(2)]
    pub transaction_witness_sets: MaybeIndefArray<T3>,

    #[n(3)]
    pub auxiliary_data_set: KeyValuePairs<TransactionIndex, T4>,

    #[n(4)]
    pub invalid_transactions: Option<MaybeIndefArray<TransactionIndex>>,
}

pub type Block = PseudoBlock<Header, TransactionBody, WitnessSet, AuxiliaryData>;

/// A memory representation of an already minted block
///
/// This structure is analogous to [Block], but it allows to retrieve the
/// original CBOR bytes for each structure that might require hashing. In this
/// way, we make sure that the resulting hash matches what exists on-chain.
pub type MintedBlock<'b> = PseudoBlock<
    KeepRaw<'b, MintedHeader<'b>>,
    KeepRaw<'b, MintedTransactionBody<'b>>,
    KeepRaw<'b, MintedWitnessSet<'b>>,
    KeepRaw<'b, AuxiliaryData>,
>;

impl<'b> From<MintedBlock<'b>> for Block {
    fn from(x: MintedBlock<'b>) -> Self {
        Block {
            header: x.header.unwrap().into(),
            transaction_bodies: MaybeIndefArray::Def(
                x.transaction_bodies
                    .iter()
                    .cloned()
                    .map(|x| x.unwrap())
                    .map(TransactionBody::from)
                    .collect(),
            ),
            transaction_witness_sets: MaybeIndefArray::Def(
                x.transaction_witness_sets
                    .iter()
                    .cloned()
                    .map(|x| x.unwrap())
                    .map(WitnessSet::from)
                    .collect(),
            ),
            auxiliary_data_set: x
                .auxiliary_data_set
                .to_vec()
                .into_iter()
                .map(|(k, v)| (k, v.unwrap()))
                .collect::<Vec<_>>()
                .into(),
            invalid_transactions: x.invalid_transactions,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Encode, Decode, Debug)]
pub struct PseudoTx<T1, T2, T3>
where
    T1: std::clone::Clone,
    T2: std::clone::Clone,
    T3: std::clone::Clone,
{
    #[n(0)]
    pub transaction_body: T1,

    #[n(1)]
    pub transaction_witness_set: T2,

    #[n(2)]
    pub success: bool,

    #[n(3)]
    pub auxiliary_data: Nullable<T3>,
}

pub type Tx = PseudoTx<TransactionBody, WitnessSet, AuxiliaryData>;

pub type MintedTx<'b> = PseudoTx<
    KeepRaw<'b, MintedTransactionBody<'b>>,
    KeepRaw<'b, MintedWitnessSet<'b>>,
    KeepRaw<'b, AuxiliaryData>,
>;

impl<'b> From<MintedTx<'b>> for Tx {
    fn from(x: MintedTx<'b>) -> Self {
        Tx {
            transaction_body: x.transaction_body.unwrap().into(),
            transaction_witness_set: x.transaction_witness_set.unwrap().into(),
            success: x.success,
            auxiliary_data: x.auxiliary_data.map(|x| x.unwrap()),
        }
    }
}

#[cfg(test)]
mod tests {
    use pallas_codec::minicbor;

    use super::MintedBlock;

    type BlockWrapper<'b> = (u16, MintedBlock<'b>);

    #[cfg(test)]
    mod tests_value {
        use super::super::AccumulatingContext;
        use super::super::Mint;
        use super::super::Multiasset;
        use super::super::NonZeroInt;
        use super::super::Value;
        use super::super::Strict;
        use pallas_codec::minicbor;
        use std::collections::BTreeMap;

        // a value can have zero coins and omit the multiasset
        #[test]
        fn decode_zero_value() {
            let ma: Strict<Value> = minicbor::decode_with(&hex::decode("00").unwrap(), &mut AccumulatingContext::new()).unwrap();
            assert_eq!(ma.inner, Value::Coin(0));
        }

        // a value can have zero coins and an empty multiasset map
        // Note: this will roundtrip back to "00"
        #[test]
        fn permit_definite_value() {
            let ma: Strict<Value> = minicbor::decode_with(&hex::decode("8200a0").unwrap(), &mut AccumulatingContext::new()).unwrap();
            assert_eq!(ma.inner, Value::Multiasset(0, Multiasset(BTreeMap::new())));
        }

        // Indefinite-encoded value is valid
        #[test]
        fn permit_indefinite_value() {
            let ma: Strict<Value> = minicbor::decode_with(&hex::decode("9f00a0ff").unwrap(), &mut AccumulatingContext::new()).unwrap();
            assert_eq!(ma.inner, Value::Multiasset(0, Multiasset(BTreeMap::new())));
        }

        // the asset sub-map of a policy map in a multiasset must not be null in Conway
        #[test]
        fn reject_null_tokens() {
            let ma: Result<Strict<Value>, _> = minicbor::decode_with(&hex::decode("8200a1581c00000000000000000000000000000000000000000000000000000000a0").unwrap(), &mut AccumulatingContext::new());
            assert_eq!(
                ma.map_err(|e| e.to_string()),
                Err("decode error: Failed strict validation: Policy must not be empty".to_owned())
            );
        }

        // the asset sub-map of a policy map in a multiasset must not have any zero values in
        // Conway
        #[test]
        fn reject_zero_tokens() {
            let ma: Result<Strict<Value>, _> = minicbor::decode_with(&hex::decode("8200a1581c00000000000000000000000000000000000000000000000000000000a14000").unwrap(), &mut AccumulatingContext::new());
            assert_eq!(
                ma.map_err(|e| e.to_string()),
                Err("decode error: PositiveCoin must not be 0".to_owned())
            );
        }

        #[test]
        fn multiasset_reject_null_tokens() {
            let ma: Result<Strict<Multiasset<NonZeroInt>>, _> = minicbor::decode_with(&hex::decode("a1581c00000000000000000000000000000000000000000000000000000000a0").unwrap(), &mut AccumulatingContext::new());
            assert_eq!(
                ma.map_err(|e| e.to_string()),
                Err("decode error: Failed strict validation: Policy must not be empty".to_owned())
            );
        }

        // the decoder for MaryValue in the haskell node rejects inputs that are "too big" as
        // defined by `isMultiAssetSmallEnough`
        #[test]
        fn multiasset_not_too_big() {
            // Creating CBOR representation of a value with 1500 policies
            // 1500 * 44 is greater than 65535 so this should fail to decode
            let mut s: String = "b905dc".to_owned();
            for i in 0..1500u16 {
                // policy
                s += "581c0000000000000000000000000000000000000000000000000000";
                s += &hex::encode(i.to_be_bytes());
                // minimal token map (conway requires nonempty asset maps)
                s += "a14001";
            }
            let ma: Result<Strict<Multiasset<NonZeroInt>>, _> = minicbor::decode_with(&hex::decode(s).unwrap(), &mut AccumulatingContext::new());
            match ma {
                Ok(_) => panic!("decode succeded but should fail"),
                Err(e) => assert_eq!(e.to_string(), "decode error: Failed strict validation: Multiasset must not exceed size limit")
            }
        }

        #[test]
        fn mint_reject_null_tokens() {
            let ma: Result<Strict<Mint>, _> = minicbor::decode_with(&hex::decode("a1581c00000000000000000000000000000000000000000000000000000000a0").unwrap(), &mut AccumulatingContext::new());
            assert_eq!(
                ma.map_err(|e| e.to_string()),
                Err("decode error: Failed strict validation: Policy must not be empty".to_owned())
            );
        }
    }

    mod tests_witness_set {
        use super::super::{AccumulatingContext, Bytes, VKeyWitness, WitnessSet, Strict};
        use pallas_codec::minicbor;

        #[test]
        fn decode_empty_witness_set() {
            let witness_set_bytes = hex::decode("a0").unwrap();
            let ws: WitnessSet = minicbor::decode_with(&witness_set_bytes, &mut AccumulatingContext::new()).unwrap();
            assert_eq!(ws.vkeywitness, None);
        }

        #[test]
        fn decode_witness_set_having_vkeywitness_untagged_must_be_nonempty() {
            let witness_set_bytes = hex::decode("a10080").unwrap();
            let ws: Result<Strict<WitnessSet>, _> = minicbor::decode_with(&witness_set_bytes, &mut AccumulatingContext::new());
            assert_eq!(
                ws.map_err(|e| e.to_string()),
                Err("decode error: decoding empty set as NonEmptySet".to_owned())
            );
        }

        #[test]
        fn decode_witness_set_having_vkeywitness_untagged_singleton() {
            let witness_set_bytes = hex::decode("a10081824040").unwrap();
            let ws: Strict<WitnessSet> = minicbor::decode_with(&witness_set_bytes, &mut AccumulatingContext::new()).unwrap();

            let expected = VKeyWitness {
                vkey: Bytes::from(vec![]),
                signature: Bytes::from(vec![]),
            };
            assert_eq!(ws.inner.vkeywitness.map(|s| s.to_vec()), Some(vec![expected]));
        }

        #[test]
        fn decode_witness_set_having_vkeywitness_conwaystyle_singleton() {
            let witness_set_bytes = hex::decode("a100d9010281824040").unwrap();
            let ws: Strict<WitnessSet> = minicbor::decode_with(&witness_set_bytes, &mut AccumulatingContext::new()).unwrap();

            let expected = VKeyWitness {
                vkey: Bytes::from(vec![]),
                signature: Bytes::from(vec![]),
            };
            assert_eq!(ws.inner.vkeywitness.map(|s| s.to_vec()), Some(vec![expected]));
        }

        #[test]
        fn decode_witness_set_having_vkeywitness_conwaystyle_must_be_nonempty() {
            let witness_set_bytes = hex::decode("a100d9010280").unwrap();
            let ws: Result<Strict<WitnessSet>, _> = minicbor::decode_with(&witness_set_bytes, &mut AccumulatingContext::new());
            assert_eq!(
                ws.map_err(|e| e.to_string()),
                Err("decode error: decoding empty set as NonEmptySet".to_owned())
            );
        }

        #[test]
        fn decode_witness_set_having_vkeywitness_reject_nonsense_tag() {
            // VKey witness set with nonsense tag 259
            let witness_set_bytes = hex::decode("a100d9010381824040").unwrap();
            let ws: Result<Strict<WitnessSet>, _> = minicbor::decode_with(&witness_set_bytes, &mut AccumulatingContext::new());
            assert_eq!(
                ws.map_err(|e| e.to_string()),
                Err("decode error: Unrecognised tag: Tag(259)".to_owned())
            );
        }

        // Unclear what the behavior should be when there are duplicates. The haskell code
        // allows duplicate entries in the CBOR but represents the vkey witnesses using a
        // set data type, so that the resulting data structure will only have one element.
        // However, our NonEmptySet type is secretly a vector and does not prevent duplicates.
        // Do we ever hash witness sets? i.e. do we need to remember the original bytes?
        #[test]
        fn decode_witness_set_having_vkeywitness_duplicate_entries() {
            let witness_set_bytes = hex::decode("a100d9010282824040824040").unwrap();
            let ws: Strict<WitnessSet> = minicbor::decode_with(&witness_set_bytes, &mut AccumulatingContext::new()).unwrap();

            let expected = VKeyWitness {
                vkey: Bytes::from(vec![]),
                signature: Bytes::from(vec![]),
            };
            assert_eq!(ws.inner.vkeywitness.map(|s| s.to_vec()), Some(vec![expected.clone(), expected]));
        }

    }

    mod tests_auxdata {
        use super::super::AuxiliaryData;
        use pallas_codec::minicbor;
        use std::collections::BTreeMap;

        #[test]
        fn decode_auxdata_shelley_format_empty() {
            let auxdata_bytes = hex::decode("a0").unwrap();
            let auxdata: AuxiliaryData =
                minicbor::decode(&auxdata_bytes).unwrap();
            match auxdata {
                AuxiliaryData::Shelley(s) => {
                    assert_eq!(s, BTreeMap::new());
                }
                _ => {
                    panic!("Unexpected variant");
                }
            }
        }

        #[test]
        fn decode_auxdata_shelley_ma_format_empty() {
            let auxdata_bytes = hex::decode("82a080").unwrap();
            let auxdata: AuxiliaryData =
                minicbor::decode(&auxdata_bytes).unwrap();
            match auxdata {
                AuxiliaryData::ShelleyMa(s) => {
                    assert_eq!(s.transaction_metadata, BTreeMap::new());
                }
                _ => {
                    panic!("Unexpected variant");
                }
            }
        }

        #[test]
        fn decode_auxdata_alonzo_format_empty() {
            let auxdata_bytes = hex::decode("d90103a0").unwrap();
            let auxdata: AuxiliaryData =
                minicbor::decode(&auxdata_bytes).unwrap();
            match auxdata {
                AuxiliaryData::PostAlonzo(a) => {
                    assert_eq!(a.metadata, None);
                }
                _ => {
                    panic!("Unexpected variant");
                }
            }
        }
    }

    mod tests_transaction {
        use super::super::{AccumulatingContext, TransactionBody, Strict};
        use pallas_codec::minicbor;

        // A simple tx with just inputs, outputs, and fee. Address is not well-formed, since the
        // 00 header implies both a payment part and a staking part are present.
        #[test]
        fn decode_simple_tx() {
            let tx_bytes = hex::decode("a300828258206767676767676767676767676767676767676767676767676767676767676767008258206767676767676767676767676767676767676767676767676767676767676767000200018182581c000000000000000000000000000000000000000000000000000000001a04000000").unwrap();
            let tx: Strict<TransactionBody> = minicbor::decode_with(&tx_bytes, &mut AccumulatingContext::new()).unwrap();
            let tx: TransactionBody = tx.inner;
            assert_eq!(tx.fee, 0);
        }

        // The decoder for ConwayTxBodyRaw rejects transaction bodies missing inputs, outputs, or
        // fee
        #[test]
        fn reject_empty_tx() {
            let tx_bytes = hex::decode("a0").unwrap();
            let tx: Result<Strict<TransactionBody<'_>>, _> = minicbor::decode_with(&tx_bytes, &mut AccumulatingContext::new());
            assert_eq!(
                tx.map_err(|e| e.to_string()),
                Err("decode error: inputs, outputs, and fee fields are required".to_owned())
            );
        }

        // Single input, no outputs, fee present but zero
        #[test]
        fn reject_tx_missing_outputs() {
            let tx_bytes = hex::decode("a200818258200000000000000000000000000000000000000000000000000000000000000008090200").unwrap();
            let tx: Result<Strict<TransactionBody<'_>>, _> = minicbor::decode_with(&tx_bytes, &mut AccumulatingContext::new());
            assert_eq!(
                tx.map_err(|e| e.to_string()),
                Err("decode error: inputs, outputs, and fee fields are required".to_owned())
            );
        }

        // Single input, single output, no fee
        #[test]
        fn reject_tx_missing_fee() {
            let tx_bytes = hex::decode("a20081825820000000000000000000000000000000000000000000000000000000000000000809018182581c000000000000000000000000000000000000000000000000000000001affffffff").unwrap();
            let tx: Result<Strict<TransactionBody<'_>>, _> = minicbor::decode_with(&tx_bytes, &mut AccumulatingContext::new());
            assert_eq!(
                tx.map_err(|e| e.to_string()),
                Err("decode error: inputs, outputs, and fee fields are required".to_owned())
            );
        }

        // The mint may not be present if it is empty
        // TODO: equivalent tests for certs, withdrawals, collateral inputs, required signer
        // hashes, reference inputs, voting procedures, and proposal procedures
        #[test]
        fn reject_empty_present_mint() {
            let tx_bytes = hex::decode("a400828258206767676767676767676767676767676767676767676767676767676767676767008258206767676767676767676767676767676767676767676767676767676767676767000200018182581c000000000000000000000000000000000000000000000000000000001a0400000009a0").unwrap();
            let tx: Result<Strict<TransactionBody<'_>>, _> = minicbor::decode_with(&tx_bytes, &mut AccumulatingContext::new());
            assert_eq!(
                tx.map_err(|e| e.to_string()),
                Err("decode error: Failed strict validation: multiasset must not be empty".to_owned())
            );
        }

        #[test]
        fn reject_empty_present_certs() {
            let tx_bytes = hex::decode("a400828258206767676767676767676767676767676767676767676767676767676767676767008258206767676767676767676767676767676767676767676767676767676767676767000200018182581c000000000000000000000000000000000000000000000000000000001a040000000480").unwrap();
            let tx: Result<Strict<TransactionBody<'_>>, _> = minicbor::decode_with(&tx_bytes, &mut AccumulatingContext::new());
            assert_eq!(
                tx.map_err(|e| e.to_string()),
                Err("decode error: decoding empty set as NonEmptySet".to_owned())
            );
        }

        #[test]
        fn reject_empty_present_withdrawals() {
            let tx_bytes = hex::decode("a400828258206767676767676767676767676767676767676767676767676767676767676767008258206767676767676767676767676767676767676767676767676767676767676767000200018182581c000000000000000000000000000000000000000000000000000000001a0400000005a0").unwrap();
            let tx: Result<Strict<TransactionBody<'_>>, _> = minicbor::decode_with(&tx_bytes, &mut AccumulatingContext::new());
            assert_eq!(
                tx.map_err(|e| e.to_string()),
                Err("decode error: Failed strict validation: map must not be empty".to_owned())
            );
        }

        #[test]
        fn reject_empty_present_collateral_inputs() {
            let tx_bytes = hex::decode("a400828258206767676767676767676767676767676767676767676767676767676767676767008258206767676767676767676767676767676767676767676767676767676767676767000200018182581c000000000000000000000000000000000000000000000000000000001a040000000d80").unwrap();
            let tx: Result<Strict<TransactionBody<'_>>, _> = minicbor::decode_with(&tx_bytes, &mut AccumulatingContext::new());
            assert_eq!(
                tx.map_err(|e| e.to_string()),
                Err("decode error: decoding empty set as NonEmptySet".to_owned())
            );
        }

        #[test]
        fn reject_empty_present_required_signers() {
            let tx_bytes = hex::decode("a400828258206767676767676767676767676767676767676767676767676767676767676767008258206767676767676767676767676767676767676767676767676767676767676767000200018182581c000000000000000000000000000000000000000000000000000000001a040000000e80").unwrap();
            let tx: Result<Strict<TransactionBody<'_>>, _> = minicbor::decode_with(&tx_bytes, &mut AccumulatingContext::new());
            assert_eq!(
                tx.map_err(|e| e.to_string()),
                Err("decode error: decoding empty set as NonEmptySet".to_owned())
            );
        }

        #[test]
        fn reject_empty_present_voting_procedures() {
            let tx_bytes = hex::decode("a400828258206767676767676767676767676767676767676767676767676767676767676767008258206767676767676767676767676767676767676767676767676767676767676767000200018182581c000000000000000000000000000000000000000000000000000000001a0400000013a0").unwrap();
            let tx: Result<Strict<TransactionBody<'_>>, _> = minicbor::decode_with(&tx_bytes, &mut AccumulatingContext::new());
            assert_eq!(
                tx.map_err(|e| e.to_string()),
                Err("decode error: Failed strict validation: map must not be empty".to_owned())
            );
        }

        #[test]
        fn reject_empty_present_proposal_procedures() {
            let tx_bytes = hex::decode("a400828258206767676767676767676767676767676767676767676767676767676767676767008258206767676767676767676767676767676767676767676767676767676767676767000200018182581c000000000000000000000000000000000000000000000000000000001a040000001480").unwrap();
            let tx: Result<Strict<TransactionBody<'_>>, _> = minicbor::decode_with(&tx_bytes, &mut AccumulatingContext::new());
            assert_eq!(
                tx.map_err(|e| e.to_string()),
                Err("decode error: decoding empty set as NonEmptySet".to_owned())
            );
        }

        #[test]
        fn reject_empty_present_donation() {
            let tx_bytes = hex::decode("a400828258206767676767676767676767676767676767676767676767676767676767676767008258206767676767676767676767676767676767676767676767676767676767676767000200018182581c000000000000000000000000000000000000000000000000000000001a040000001600").unwrap();
            let tx: Result<Strict<TransactionBody<'_>>, _> = minicbor::decode_with(&tx_bytes, &mut AccumulatingContext::new());
            assert_eq!(
                tx.map_err(|e| e.to_string()),
                Err("decode error: PositiveCoin must not be 0".to_owned())
            );
        }


        #[test]
        fn reject_duplicate_keys() {
            let tx_bytes = hex::decode("a40081825820000000000000000000000000000000000000000000000000000000000000000809018182581c000000000000000000000000000000000000000000000000000000001affffffff02010201").unwrap();
            let tx: Result<Strict<TransactionBody<'_>>, _> = minicbor::decode_with(&tx_bytes, &mut AccumulatingContext::new());
            assert_eq!(
                tx.map_err(|e| e.to_string()),
                Err("decode error: Failed strict validation: duplicate txbody entries for key 2".to_owned())
            );
        }
    }

    #[cfg(test)]
    mod tests_voter {
        use super::super::Voter;
        use crate::Hash;
        use std::cmp::Ordering;
        use test_case::test_case;

        fn fake_hash(prefix: &str) -> Hash<28> {
            let null_hash: [u8; 28] = [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ];
            Hash::from(&[prefix.as_bytes(), &null_hash].concat()[0..28])
        }

        fn cc_script(prefix: &str) -> Voter {
            Voter::ConstitutionalCommitteeScript(fake_hash(prefix))
        }

        fn cc_key(prefix: &str) -> Voter {
            Voter::ConstitutionalCommitteeKey(fake_hash(prefix))
        }

        fn drep_script(prefix: &str) -> Voter {
            Voter::DRepScript(fake_hash(prefix))
        }

        fn drep_key(prefix: &str) -> Voter {
            Voter::DRepKey(fake_hash(prefix))
        }

        fn spo(prefix: &str) -> Voter {
            Voter::StakePoolKey(fake_hash(prefix))
        }

        #[test_case(cc_script("alice"), cc_script("alice") => Ordering::Equal)]
        #[test_case(cc_script("alice"), cc_key("alice") => Ordering::Less)]
        #[test_case(cc_script("alice"), drep_script("alice") => Ordering::Less)]
        #[test_case(cc_script("alice"), drep_key("alice") => Ordering::Less)]
        #[test_case(cc_script("alice"), spo("alice") => Ordering::Less)]
        #[test_case(cc_script("bob"), cc_script("alice") => Ordering::Greater)]
        #[test_case(drep_script("alice"), cc_script("alice") => Ordering::Greater)]
        #[test_case(drep_script("alice"), cc_key("alice") => Ordering::Greater)]
        #[test_case(drep_script("alice"), drep_script("alice") => Ordering::Equal)]
        #[test_case(drep_script("alice"), drep_key("alice") => Ordering::Less)]
        #[test_case(drep_script("alice"), spo("alice") => Ordering::Less)]
        #[test_case(drep_script("bob"), drep_script("alice") => Ordering::Greater)]
        fn voter_ordering(left: Voter, right: Voter) -> Ordering {
            left.cmp(&right)
        }
    }

    #[test]
    fn block_isomorphic_decoding_encoding() {
        let test_blocks = [
            include_str!("../../../test_data/conway1.block"),
            include_str!("../../../test_data/conway2.block"),
            // interesting block with extreme values
            include_str!("../../../test_data/conway3.block"),
            // interesting block with extreme values
            include_str!("../../../test_data/conway4.block"),
        ];

        for (idx, block_str) in test_blocks.iter().enumerate() {
            println!("decoding test block {}", idx + 1);
            let bytes = hex::decode(block_str).unwrap_or_else(|_| panic!("bad block file {idx}"));

            let block: BlockWrapper = minicbor::decode(&bytes)
                .unwrap_or_else(|e| panic!("error decoding cbor for file {idx}: {e:?}"));

            let bytes2 = minicbor::to_vec(block)
                .unwrap_or_else(|e| panic!("error encoding block cbor for file {idx}: {e:?}"));

            assert!(bytes.eq(&bytes2), "re-encoded bytes didn't match original");
        }
    }

    // #[test]
    // fn fragments_decoding() {
    //     // peculiar array of outputs used in an hydra transaction
    //     let bytes = hex::decode(hex).unwrap();
    //     let outputs =
    // Vec::<TransactionOutput>::decode_fragment(&bytes).unwrap();
    //
    //     dbg!(outputs);
    //
    //     // add any loose fragment tests here
    // }
}
