use op_alloy_consensus::DepositTransaction;
use reth_primitives_traits::{FillTxEnv, InMemorySize, SignedTransaction};
use revm_primitives::{AuthorizationList, TxEnv};
use std::mem;

use alloy_consensus::{
    transaction::{from_eip155_value, RlpEcdsaTx},
    TxEip1559, TxEip2930, TxEip4844, TxEip7702, TxLegacy,
};
use alloy_eips::{
    eip2718::{Decodable2718, Eip2718Error, Eip2718Result, Encodable2718},
    eip2930::AccessList,
    eip7702::SignedAuthorization,
};
use alloy_primitives::{
    keccak256, Address, Bytes, ChainId, PrimitiveSignature as Signature, TxHash, TxKind, B256, U256,
};
use alloy_rlp::{Decodable, Encodable, Error as RlpError};
use derive_more::{AsRef, Deref};
use op_alloy_consensus::TxDeposit;
use reth_primitives::{
    create_tx_compressor, create_tx_decompressor,
    transaction::{recover_signer, recover_signer_unchecked, Transaction, TxType},
    TRANSACTION_COMPRESSOR, TRANSACTION_DECOMPRESSOR,
};
use serde::{Deserialize, Serialize};

/// Signed transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, AsRef, Deref, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::add_arbitrary_tests(compact))]
pub struct TransactionSigned {
    /// Transaction hash
    pub hash: TxHash,
    /// The transaction signature values
    pub signature: Signature,
    /// Raw transaction info
    #[deref]
    #[as_ref]
    pub transaction: Transaction,
}

impl Default for TransactionSigned {
    fn default() -> Self {
        Self {
            hash: Default::default(),
            signature: Signature::test_signature(),
            transaction: Default::default(),
        }
    }
}

impl AsRef<Self> for TransactionSigned {
    fn as_ref(&self) -> &Self {
        self
    }
}

// === impl TransactionSigned ===
impl TransactionSigned {
    /// Calculate transaction hash, eip2728 transaction does not contain rlp header and start with
    /// tx type.
    pub fn recalculate_hash(&self) -> B256 {
        keccak256(self.encoded_2718())
    }

    /// Create a new signed transaction from a transaction and its signature.
    ///
    /// This will also calculate the transaction hash using its encoding.
    pub fn from_transaction_and_signature(transaction: Transaction, signature: Signature) -> Self {
        let mut initial_tx = Self { transaction, hash: Default::default(), signature };
        initial_tx.hash = initial_tx.recalculate_hash();
        initial_tx
    }

    /// Decodes legacy transaction from the data buffer into a tuple.
    ///
    /// This expects `rlp(legacy_tx)`
    ///
    /// Refer to the docs for [`Self::decode_rlp_legacy_transaction`] for details on the exact
    /// format expected.
    pub(crate) fn decode_rlp_legacy_transaction_tuple(
        data: &mut &[u8],
    ) -> alloy_rlp::Result<(TxLegacy, TxHash, Signature)> {
        let original_encoding = *data;

        let header = alloy_rlp::Header::decode(data)?;
        let remaining_len = data.len();

        let transaction_payload_len = header.payload_length;

        if transaction_payload_len > remaining_len {
            return Err(RlpError::InputTooShort);
        }

        let mut transaction = TxLegacy {
            nonce: Decodable::decode(data)?,
            gas_price: Decodable::decode(data)?,
            gas_limit: Decodable::decode(data)?,
            to: Decodable::decode(data)?,
            value: Decodable::decode(data)?,
            input: Decodable::decode(data)?,
            chain_id: None,
        };

        let v = Decodable::decode(data)?;
        let r: U256 = Decodable::decode(data)?;
        let s: U256 = Decodable::decode(data)?;

        let tx_length = header.payload_length + header.length();
        let hash = keccak256(&original_encoding[..tx_length]);

        // Handle both pre-bedrock and regular cases
        let (signature, chain_id) = if v == 0 && r.is_zero() && s.is_zero() {
            // Pre-bedrock system transactions case
            (Signature::new(r, s, false), None)
        } else {
            // Regular transaction case
            let (parity, chain_id) = from_eip155_value(v)
                .ok_or(alloy_rlp::Error::Custom("invalid parity for legacy transaction"))?;
            (Signature::new(r, s, parity), chain_id)
        };

        // Set chain ID and verify length
        transaction.chain_id = chain_id;
        let decoded = remaining_len - data.len();
        if decoded != transaction_payload_len {
            return Err(RlpError::UnexpectedLength);
        }

        Ok((transaction, hash, signature))
    }

    /// Decodes legacy transaction from the data buffer.
    ///
    /// This should be used _only_ be used in general transaction decoding methods, which have
    /// already ensured that the input is a legacy transaction with the following format:
    /// `rlp(legacy_tx)`
    ///
    /// Legacy transactions are encoded as lists, so the input should start with a RLP list header.
    ///
    /// This expects `rlp(legacy_tx)`
    // TODO: make buf advancement semantics consistent with `decode_enveloped_typed_transaction`,
    // so decoding methods do not need to manually advance the buffer
    pub fn decode_rlp_legacy_transaction(data: &mut &[u8]) -> alloy_rlp::Result<Self> {
        let (transaction, hash, signature) = Self::decode_rlp_legacy_transaction_tuple(data)?;
        let signed = Self { transaction: Transaction::Legacy(transaction), hash, signature };
        Ok(signed)
    }
}

impl SignedTransaction for TransactionSigned {
    type Transaction = Transaction;

    fn tx_hash(&self) -> &TxHash {
        &self.hash
    }

    fn transaction(&self) -> &Self::Transaction {
        &self.transaction
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn recover_signer(&self) -> Option<Address> {
        let signature_hash = self.signature_hash();
        recover_signer(&self.signature, signature_hash)
    }

    fn recover_signer_unchecked(&self) -> Option<Address> {
        let signature_hash = self.signature_hash();
        recover_signer_unchecked(&self.signature, signature_hash)
    }
}

impl Decodable for TransactionSigned {
    /// This `Decodable` implementation only supports decoding rlp encoded transactions as it's used
    /// by p2p.
    ///
    /// The p2p encoding format always includes an RLP header, although the type RLP header depends
    /// on whether or not the transaction is a legacy transaction.
    ///
    /// If the transaction is a legacy transaction, it is just encoded as a RLP list:
    /// `rlp(tx-data)`.
    ///
    /// If the transaction is a typed transaction, it is encoded as a RLP string:
    /// `rlp(tx-type || rlp(tx-data))`
    ///
    /// This can be used for decoding all signed transactions in p2p `BlockBodies` responses.
    ///
    /// This cannot be used for decoding EIP-4844 transactions in p2p `PooledTransactions`, since
    /// the EIP-4844 variant of [`TransactionSigned`] does not include the blob sidecar.
    ///
    /// For a method suitable for decoding pooled transactions, see \[`PooledTransactionsElement`\].
    ///
    /// CAUTION: Due to a quirk in [`Header::decode`], this method will succeed even if a typed
    /// transaction is encoded in this format, and does not start with a RLP header:
    /// `tx-type || rlp(tx-data)`.
    ///
    /// This is because [`Header::decode`] does not advance the buffer, and returns a length-1
    /// string header if the first byte is less than `0xf7`.
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Self::network_decode(buf).map_err(Into::into)
    }
}

impl FillTxEnv for TransactionSigned {
    fn fill_tx_env(&self, tx_env: &mut TxEnv, sender: Address) {
        tx_env.caller = sender;
        match self.as_ref() {
            Transaction::Legacy(tx) => {
                tx_env.gas_limit = tx.gas_limit;
                tx_env.gas_price = U256::from(tx.gas_price);
                tx_env.gas_priority_fee = None;
                tx_env.transact_to = tx.to;
                tx_env.value = tx.value;
                tx_env.data = tx.input.clone();
                tx_env.chain_id = tx.chain_id;
                tx_env.nonce = Some(tx.nonce);
                tx_env.access_list.clear();
                tx_env.blob_hashes.clear();
                tx_env.max_fee_per_blob_gas.take();
                tx_env.authorization_list = None;
            }
            Transaction::Eip2930(tx) => {
                tx_env.gas_limit = tx.gas_limit;
                tx_env.gas_price = U256::from(tx.gas_price);
                tx_env.gas_priority_fee = None;
                tx_env.transact_to = tx.to;
                tx_env.value = tx.value;
                tx_env.data = tx.input.clone();
                tx_env.chain_id = Some(tx.chain_id);
                tx_env.nonce = Some(tx.nonce);
                tx_env.access_list.clone_from(&tx.access_list.0);
                tx_env.blob_hashes.clear();
                tx_env.max_fee_per_blob_gas.take();
                tx_env.authorization_list = None;
            }
            Transaction::Eip1559(tx) => {
                tx_env.gas_limit = tx.gas_limit;
                tx_env.gas_price = U256::from(tx.max_fee_per_gas);
                tx_env.gas_priority_fee = Some(U256::from(tx.max_priority_fee_per_gas));
                tx_env.transact_to = tx.to;
                tx_env.value = tx.value;
                tx_env.data = tx.input.clone();
                tx_env.chain_id = Some(tx.chain_id);
                tx_env.nonce = Some(tx.nonce);
                tx_env.access_list.clone_from(&tx.access_list.0);
                tx_env.blob_hashes.clear();
                tx_env.max_fee_per_blob_gas.take();
                tx_env.authorization_list = None;
            }
            Transaction::Eip4844(tx) => {
                tx_env.gas_limit = tx.gas_limit;
                tx_env.gas_price = U256::from(tx.max_fee_per_gas);
                tx_env.gas_priority_fee = Some(U256::from(tx.max_priority_fee_per_gas));
                tx_env.transact_to = TxKind::Call(tx.to);
                tx_env.value = tx.value;
                tx_env.data = tx.input.clone();
                tx_env.chain_id = Some(tx.chain_id);
                tx_env.nonce = Some(tx.nonce);
                tx_env.access_list.clone_from(&tx.access_list.0);
                tx_env.blob_hashes.clone_from(&tx.blob_versioned_hashes);
                tx_env.max_fee_per_blob_gas = Some(U256::from(tx.max_fee_per_blob_gas));
                tx_env.authorization_list = None;
            }
            Transaction::Eip7702(tx) => {
                tx_env.gas_limit = tx.gas_limit;
                tx_env.gas_price = U256::from(tx.max_fee_per_gas);
                tx_env.gas_priority_fee = Some(U256::from(tx.max_priority_fee_per_gas));
                tx_env.transact_to = tx.to.into();
                tx_env.value = tx.value;
                tx_env.data = tx.input.clone();
                tx_env.chain_id = Some(tx.chain_id);
                tx_env.nonce = Some(tx.nonce);
                tx_env.access_list.clone_from(&tx.access_list.0);
                tx_env.blob_hashes.clear();
                tx_env.max_fee_per_blob_gas.take();
                tx_env.authorization_list =
                    Some(AuthorizationList::Signed(tx.authorization_list.clone()));
            }
            Transaction::Deposit(_) => {}
        }
    }
}

impl InMemorySize for TransactionSigned {
    fn size(&self) -> usize {
        mem::size_of::<TxHash>() + self.transaction.size() + mem::size_of::<Signature>()
    }
}

impl alloy_consensus::Transaction for TransactionSigned {
    fn chain_id(&self) -> Option<ChainId> {
        self.deref().chain_id()
    }

    fn nonce(&self) -> u64 {
        self.deref().nonce()
    }

    fn gas_limit(&self) -> u64 {
        self.deref().gas_limit()
    }

    fn gas_price(&self) -> Option<u128> {
        self.deref().gas_price()
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.deref().max_fee_per_gas()
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.deref().max_priority_fee_per_gas()
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        self.deref().max_fee_per_blob_gas()
    }

    fn priority_fee_or_price(&self) -> u128 {
        self.deref().priority_fee_or_price()
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        self.deref().effective_gas_price(base_fee)
    }

    fn is_dynamic_fee(&self) -> bool {
        self.deref().is_dynamic_fee()
    }

    fn kind(&self) -> TxKind {
        self.deref().kind()
    }

    fn value(&self) -> U256 {
        self.deref().value()
    }

    fn input(&self) -> &Bytes {
        self.deref().input()
    }

    fn ty(&self) -> u8 {
        self.deref().ty()
    }

    fn access_list(&self) -> Option<&AccessList> {
        self.deref().access_list()
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        alloy_consensus::Transaction::blob_versioned_hashes(self.deref())
    }

    fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
        self.deref().authorization_list()
    }
}

impl Encodable2718 for TransactionSigned {
    fn type_flag(&self) -> Option<u8> {
        match self.transaction.tx_type() {
            TxType::Legacy => None,
            tx_type => Some(tx_type as u8),
        }
    }

    fn encode_2718_len(&self) -> usize {
        match &self.transaction {
            Transaction::Legacy(legacy_tx) => legacy_tx.eip2718_encoded_length(&self.signature),
            Transaction::Eip2930(access_list_tx) => {
                access_list_tx.eip2718_encoded_length(&self.signature)
            }
            Transaction::Eip1559(dynamic_fee_tx) => {
                dynamic_fee_tx.eip2718_encoded_length(&self.signature)
            }
            Transaction::Eip4844(blob_tx) => blob_tx.eip2718_encoded_length(&self.signature),
            Transaction::Eip7702(set_code_tx) => {
                set_code_tx.eip2718_encoded_length(&self.signature)
            }
            Transaction::Deposit(deposit_tx) => deposit_tx.eip2718_encoded_length(),
        }
    }
    fn encode_2718(&self, out: &mut dyn alloy_rlp::BufMut) {
        self.transaction.eip2718_encode(&self.signature, out)
    }
}

impl Decodable2718 for TransactionSigned {
    fn typed_decode(ty: u8, buf: &mut &[u8]) -> Eip2718Result<Self> {
        match ty.try_into().map_err(|_| Eip2718Error::UnexpectedType(ty))? {
            TxType::Legacy => Err(Eip2718Error::UnexpectedType(0)),
            TxType::Eip2930 => {
                let (tx, signature, hash) = TxEip2930::rlp_decode_signed(buf)?.into_parts();
                Ok(Self { transaction: Transaction::Eip2930(tx), signature, hash })
            }
            TxType::Eip1559 => {
                let (tx, signature, hash) = TxEip1559::rlp_decode_signed(buf)?.into_parts();
                Ok(Self { transaction: Transaction::Eip1559(tx), signature, hash })
            }
            TxType::Eip7702 => {
                let (tx, signature, hash) = TxEip7702::rlp_decode_signed(buf)?.into_parts();
                Ok(Self { transaction: Transaction::Eip7702(tx), signature, hash })
            }
            TxType::Eip4844 => {
                let (tx, signature, hash) = TxEip4844::rlp_decode_signed(buf)?.into_parts();
                Ok(Self { transaction: Transaction::Eip4844(tx), signature, hash })
            }
            TxType::Deposit => Ok(Self::from_transaction_and_signature(
                Transaction::Deposit(TxDeposit::rlp_decode(buf)?),
                TxDeposit::signature(),
            )),
        }
    }

    fn fallback_decode(buf: &mut &[u8]) -> Eip2718Result<Self> {
        Ok(Self::decode_rlp_legacy_transaction(buf)?)
    }
}

impl Encodable for TransactionSigned {
    /// This encodes the transaction _with_ the signature, and an rlp header.
    ///
    /// For legacy transactions, it encodes the transaction data:
    /// `rlp(tx-data)`
    ///
    /// For EIP-2718 typed transactions, it encodes the transaction type followed by the rlp of the
    /// transaction:
    /// `rlp(tx-type || rlp(tx-data))`
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        self.network_encode(out);
    }

    fn length(&self) -> usize {
        let mut payload_length = self.encode_2718_len();
        if !self.is_legacy() {
            payload_length += alloy_rlp::Header { list: false, payload_length }.length();
        }

        payload_length
    }
}

#[cfg(any(test, feature = "reth-codec"))]
impl reth_codecs::Compact for TransactionSigned {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        let tx: TransactionSignedNoHash = self.clone().into();
        tx.to_compact(buf)
    }

    fn from_compact(buf: &[u8], len: usize) -> (Self, &[u8]) {
        let (tx, buf) = TransactionSignedNoHash::from_compact(buf, len);
        (tx.into(), buf)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for TransactionSigned {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        #[allow(unused_mut)]
        let mut transaction = Transaction::arbitrary(u)?;

        let secp = secp256k1::Secp256k1::new();
        let key_pair = secp256k1::Keypair::new(&secp, &mut rand::thread_rng());
        let signature = reth_primitives::sign_message(
            B256::from_slice(&key_pair.secret_bytes()[..]),
            transaction.signature_hash(),
        )
        .unwrap();

        // Both `Some(0)` and `None` values are encoded as empty string byte. This introduces
        // ambiguity in roundtrip tests. Patch the mint value of deposit transaction here, so that
        // it's `None` if zero.
        if let Transaction::Deposit(ref mut tx_deposit) = transaction {
            if tx_deposit.mint == Some(0) {
                tx_deposit.mint = None;
            }
        }

        let signature = if transaction.is_deposit() { TxDeposit::signature() } else { signature };

        Ok(Self::from_transaction_and_signature(transaction, signature))
    }
}

/// Signed transaction without its Hash. Used type for inserting into the DB.
///
/// This can by converted to [`TransactionSigned`] by calling [`TransactionSignedNoHash::hash`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, AsRef, Deref, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "reth-codec"), reth_codecs::add_arbitrary_tests(compact))]
pub struct TransactionSignedNoHash {
    /// The transaction signature values
    pub signature: Signature,
    /// Raw transaction info
    #[deref]
    #[as_ref]
    pub transaction: Transaction,
}

impl TransactionSignedNoHash {
    /// Calculates the transaction hash. If used more than once, it's better to convert it to
    /// [`TransactionSigned`] first.
    pub fn hash(&self) -> B256 {
        // pre-allocate buffer for the transaction
        let mut buf = Vec::with_capacity(128 + self.transaction.input().len());
        self.transaction.eip2718_encode(&self.signature, &mut buf);
        keccak256(&buf)
    }

    /// Recover signer from signature and hash.
    ///
    /// Returns `None` if the transaction's signature is invalid, see also [`Self::recover_signer`].
    pub fn recover_signer(&self) -> Option<Address> {
        // Optimism's Deposit transaction does not have a signature. Directly return the
        // `from` address.
        if let Transaction::Deposit(TxDeposit { from, .. }) = self.transaction {
            return Some(from)
        }

        let signature_hash = self.signature_hash();
        recover_signer(&self.signature, signature_hash)
    }

    /// Recover signer from signature and hash _without ensuring that the signature has a low `s`
    /// value_.
    ///
    /// Reuses a given buffer to avoid numerous reallocations when recovering batches. **Clears the
    /// buffer before use.**
    ///
    /// Returns `None` if the transaction's signature is invalid, see also
    /// [`recover_signer_unchecked`].
    ///
    /// # Optimism
    ///
    /// For optimism this will return [`Address::ZERO`] if the Signature is empty, this is because pre bedrock (on OP mainnet), relay messages to the L2 Cross Domain Messenger were sent as legacy transactions from the zero address with an empty signature, e.g.: <https://optimistic.etherscan.io/tx/0x1bb352ff9215efe5a4c102f45d730bae323c3288d2636672eb61543ddd47abad>
    /// This makes it possible to import pre bedrock transactions via the sender recovery stage.
    pub fn encode_and_recover_unchecked(&self, buffer: &mut Vec<u8>) -> Option<Address> {
        buffer.clear();
        self.transaction.encode_for_signing(buffer);

        // Optimism's Deposit transaction does not have a signature. Directly return the
        // `from` address.
        {
            if let Transaction::Deposit(TxDeposit { from, .. }) = self.transaction {
                return Some(from)
            }

            // pre bedrock system transactions were sent from the zero address as legacy
            // transactions with an empty signature
            //
            // NOTE: this is very hacky and only relevant for op-mainnet pre bedrock
            if self.is_legacy() && self.signature == TxDeposit::signature() {
                return Some(Address::ZERO)
            }
        }

        recover_signer_unchecked(&self.signature, keccak256(buffer))
    }

    /// Converts into a transaction type with its hash: [`TransactionSigned`].
    ///
    /// Note: This will recalculate the hash of the transaction.
    #[inline]
    pub fn with_hash(self) -> TransactionSigned {
        let Self { signature, transaction } = self;
        TransactionSigned::from_transaction_and_signature(transaction, signature)
    }
}

impl Default for TransactionSignedNoHash {
    fn default() -> Self {
        Self { signature: Signature::test_signature(), transaction: Default::default() }
    }
}

#[cfg(any(test, feature = "arbitrary"))]
impl<'a> arbitrary::Arbitrary<'a> for TransactionSignedNoHash {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let tx_signed = TransactionSigned::arbitrary(u)?;

        Ok(Self { signature: tx_signed.signature, transaction: tx_signed.transaction })
    }
}

#[cfg(any(test, feature = "reth-codec"))]
impl reth_codecs::Compact for TransactionSignedNoHash {
    fn to_compact<B>(&self, buf: &mut B) -> usize
    where
        B: bytes::BufMut + AsMut<[u8]>,
    {
        let start = buf.as_mut().len();

        // Placeholder for bitflags.
        // The first byte uses 4 bits as flags: IsCompressed[1bit], TxType[2bits], Signature[1bit]
        buf.put_u8(0);

        let sig_bit = self.signature.to_compact(buf) as u8;
        let zstd_bit = self.transaction.input().len() >= 32;

        let tx_bits = if zstd_bit {
            let mut tmp = Vec::with_capacity(256);
            if cfg!(feature = "std") {
                TRANSACTION_COMPRESSOR.with(|compressor| {
                    let mut compressor = compressor.borrow_mut();
                    let tx_bits = self.transaction.to_compact(&mut tmp);
                    buf.put_slice(&compressor.compress(&tmp).expect("Failed to compress"));
                    tx_bits as u8
                })
            } else {
                let mut compressor = create_tx_compressor();
                let tx_bits = self.transaction.to_compact(&mut tmp);
                buf.put_slice(&compressor.compress(&tmp).expect("Failed to compress"));
                tx_bits as u8
            }
        } else {
            self.transaction.to_compact(buf) as u8
        };

        // Replace bitflags with the actual values
        buf.as_mut()[start] = sig_bit | (tx_bits << 1) | ((zstd_bit as u8) << 3);

        buf.as_mut().len() - start
    }

    fn from_compact(mut buf: &[u8], _len: usize) -> (Self, &[u8]) {
        use bytes::Buf;

        // The first byte uses 4 bits as flags: IsCompressed[1], TxType[2], Signature[1]
        let bitflags = buf.get_u8() as usize;

        let sig_bit = bitflags & 1;
        let (signature, buf) = Signature::from_compact(buf, sig_bit);

        let zstd_bit = bitflags >> 3;
        let (transaction, buf) = if zstd_bit != 0 {
            if cfg!(feature = "std") {
                TRANSACTION_DECOMPRESSOR.with(|decompressor| {
                    let mut decompressor = decompressor.borrow_mut();

                    // TODO: enforce that zstd is only present at a "top" level type

                    let transaction_type = (bitflags & 0b110) >> 1;
                    let (transaction, _) =
                        Transaction::from_compact(decompressor.decompress(buf), transaction_type);

                    (transaction, buf)
                })
            } else {
                let mut decompressor = create_tx_decompressor();
                let transaction_type = (bitflags & 0b110) >> 1;
                let (transaction, _) =
                    Transaction::from_compact(decompressor.decompress(buf), transaction_type);

                (transaction, buf)
            }
        } else {
            let transaction_type = bitflags >> 1;
            Transaction::from_compact(buf, transaction_type)
        };

        (Self { signature, transaction }, buf)
    }
}

impl From<TransactionSignedNoHash> for TransactionSigned {
    fn from(tx: TransactionSignedNoHash) -> Self {
        tx.with_hash()
    }
}

impl From<TransactionSigned> for TransactionSignedNoHash {
    fn from(tx: TransactionSigned) -> Self {
        Self { signature: tx.signature, transaction: tx.transaction }
    }
}

#[cfg(test)]
mod tests {
    use crate::transaction::TransactionSigned;
    use alloy_primitives::{address, hex, TxKind, B256, U256};
    use reth_primitives::transaction::Transaction;
    const DEPOSIT_FUNCTION_SELECTOR: [u8; 4] = [0xb6, 0xb5, 0x5f, 0x25];
    use alloy_rlp::Decodable;

    #[test]
    fn test_decode_legacy_transactions() {
        // Test Case 1: contract deposit - regular L2 transaction calling deposit() function
        // tx: https://optimistic.etherscan.io/getRawTx?tx=0x7860252963a2df21113344f323035ef59648638a571eef742e33d789602c7a1c
        let deposit_tx_bytes = hex!("f88881f0830f481c830c6e4594a75127121d28a9bf848f3b70e7eea26570aa770080a4b6b55f2500000000000000000000000000000000000000000000000000000000000710b238a0d5c622d92ddf37f9c18a3465a572f74d8b1aeaf50c1cfb10b3833242781fd45fa02c4f1d5819bf8b70bf651e7a063b7db63c55bd336799c6ae3e5bc72ad6ef3def");
        let deposit_decoded = TransactionSigned::decode(&mut &deposit_tx_bytes[..]).unwrap();

        // Verify deposit transaction
        let deposit_tx = match &deposit_decoded.transaction {
            Transaction::Legacy(ref tx) => tx,
            _ => panic!("Expected legacy transaction for NFT deposit"),
        };

        assert_eq!(
            deposit_tx.to,
            TxKind::Call(address!("a75127121d28a9bf848f3b70e7eea26570aa7700"))
        );
        assert_eq!(deposit_tx.nonce, 240);
        assert_eq!(deposit_tx.gas_price, 1001500);
        assert_eq!(deposit_tx.gas_limit, 814661);
        assert_eq!(deposit_tx.value, U256::ZERO);
        assert_eq!(&deposit_tx.input.as_ref()[0..4], DEPOSIT_FUNCTION_SELECTOR);
        assert_eq!(deposit_tx.chain_id, Some(10));
        assert_eq!(
            deposit_decoded.signature.r(),
            U256::from_str_radix(
                "d5c622d92ddf37f9c18a3465a572f74d8b1aeaf50c1cfb10b3833242781fd45f",
                16
            )
            .unwrap()
        );
        assert_eq!(
            deposit_decoded.signature.s(),
            U256::from_str_radix(
                "2c4f1d5819bf8b70bf651e7a063b7db63c55bd336799c6ae3e5bc72ad6ef3def",
                16
            )
            .unwrap()
        );

        // Test Case 2: pre-bedrock system transaction from block 105235052
        // tx: https://optimistic.etherscan.io/getRawTx?tx=0xe20b11349681dd049f8df32f5cdbb4c68d46b537685defcd86c7fa42cfe75b9e
        let system_tx_bytes = hex!("f9026c830d899383124f808302a77e94a0cc33dd6f4819d473226257792afe230ec3c67f80b902046c459a280000000000000000000000004d73adb72bc3dd368966edd0f0b2148401a178e2000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000647fac7f00000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000084704316e5000000000000000000000000000000000000000000000000000000000000006e10975631049de3c008989b0d8c19fc720dc556ca01abfbd794c6eb5075dd000d000000000000000000000000000000000000000000000000000000000000001410975631049de3c008989b0d8c19fc720dc556ca01abfbd794c6eb5075dd000d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000082a39325251d44e11f3b6d92f9382438eb6c8b5068d4a488d4f177b26f2ca20db34ae53467322852afcc779f25eafd124c5586f54b9026497ba934403d4c578e3c1b5aa754c918ee2ecd25402df656c2419717e4017a7aecb84af3914fd3c7bf6930369c4e6ff76950246b98e354821775f02d33cdbee5ef6aed06c15b75691692d31c00000000000000000000000000000000000000000000000000000000000038a0e8991e95e66d809f4b6fb0af27c31368ca0f30e657165c428aa681ec5ea25bbea013ed325bd97365087ec713e9817d252b59113ea18430b71a5890c4eeb6b9efc4");
        let system_decoded = TransactionSigned::decode(&mut &system_tx_bytes[..]).unwrap();

        // Verify system transaction
        assert!(system_decoded.is_legacy());

        let system_tx = match &system_decoded.transaction {
            Transaction::Legacy(ref tx) => tx,
            _ => panic!("Expected Legacy transaction"),
        };

        assert_eq!(system_tx.nonce, 887187);
        assert_eq!(system_tx.gas_price, 1200000);
        assert_eq!(system_tx.gas_limit, 173950);
        assert_eq!(
            system_tx.to,
            TxKind::Call(address!("a0cc33dd6f4819d473226257792afe230ec3c67f"))
        );
        assert_eq!(system_tx.value, U256::ZERO);
        assert_eq!(system_tx.chain_id, Some(10));

        assert_eq!(
            system_decoded.signature.r(),
            U256::from_str_radix(
                "e8991e95e66d809f4b6fb0af27c31368ca0f30e657165c428aa681ec5ea25bbe",
                16
            )
            .unwrap()
        );
        assert_eq!(
            system_decoded.signature.s(),
            U256::from_str_radix(
                "13ed325bd97365087ec713e9817d252b59113ea18430b71a5890c4eeb6b9efc4",
                16
            )
            .unwrap()
        );
        assert_eq!(
            system_decoded.hash,
            B256::from(hex!("e20b11349681dd049f8df32f5cdbb4c68d46b537685defcd86c7fa42cfe75b9e"))
        );
    }
}
