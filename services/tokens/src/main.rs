#![no_std]
#![no_main]

extern crate alloc;

use std::collections::HashMap;
use std::fmt;
use std::hash::Hash;
use secp256k1::{Message, PublicKey, Secp256k1, Signature, recover, RecoveryId};
use sha3::{Digest, Keccak256};
use rand::Rng;
use alloc::vec::Vec;
use simplealloc::SimpleAlloc;

#[global_allocator]
static ALLOCATOR: SimpleAlloc<4096> = SimpleAlloc::new();

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::arch::asm!("unimp", options(noreturn));
    }
}

#[polkavm_derive::polkavm_import]
extern "C" {
    #[polkavm_import(index = 2)]
    pub fn read(service: u32, key_ptr: *const u8, key_len: u32, out: *mut u8, out_len: u32) -> u32;
    #[polkavm_import(index = 3)]
    pub fn write(key_ptr: *const u8, key_len: u32, value: *const u8, value_len: u32) -> u32;
    #[polkavm_import(index = 101)]
    pub fn ecrecover(h: *const u8, v: *const u8, r: *const u8, s: *const u8, out: *mut u8) -> u32;
    #[polkavm_import(index = 102)]
    pub fn sha2_256(data: *const u8, data_len: u32, hash_ptr: *mut u8) -> u32;
}

#[polkavm_derive::polkavm_export]
extern "C" fn is_authorized() -> u32 {
    0
}

#[polkavm_derive::polkavm_export]
extern "C" fn refine() -> u32 {
    0
}

#[polkavm_derive::polkavm_export]
extern "C" fn accumulate() -> u32 {
    0
}

#[polkavm_derive::polkavm_export]
extern "C" fn on_transfer() -> u32 {
    0
}

// Define TokenID as a 20-byte array
type TokenID = [u8; 20];

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum ControlledAccessType {
    Deny,
    Allow,
}



#[derive(Debug)]
pub enum TokenMessage<AccountId: Eq + Hash + Clone + fmt::Debug> {
    New {
        name: String,
        symbol: String,
        decimals: u8,
        initial_supply: u128,
        controlled_access_type: ControlledAccessType,
        automator: AccountId,
        client: AccountId,
        default_admin: AccountId,
        upgrader: AccountId,
        signature: Signature,
    },
    Mint {
        token_id: TokenID,
        to: AccountId,
        amount: u128,
        signature: Signature,
    },
    Burn {
        token_id: TokenID,
        from: AccountId,
        amount: u128,
        signature: Signature,
    },
    Pause {
        token_id: TokenID,
        sender: AccountId,
        signature: Signature,
    },
    Unpause {
        token_id: TokenID,
        sender: AccountId,
        signature: Signature,
    },
    Transfer {
        token_id: TokenID,
        from: AccountId,
        to: AccountId,
        amount: u128,
        signature: Signature,
    },
    Approve {
        token_id: TokenID,
        owner: AccountId,
        spender: AccountId,
        amount: u128,
        signature: Signature,
    },
    Permit {
        token_id: TokenID,
        owner: AccountId,
        spender: AccountId,
        value: u128,
        deadline: u64,
        v: u8,
        r: [u8; 32],
        s: [u8; 32],
        signature: Signature,
    },
}



pub struct TokenState<AccountId: Eq + Hash + Clone + fmt::Debug> {
    tokens: HashMap<TokenID, SingleTokenState<AccountId>>,
}

impl<AccountId: Eq + Hash + Clone + fmt::Debug> Default for TokenState<AccountId> {
    fn default() -> Self {
        TokenState {
            tokens: HashMap::new(),
        }
    }
}

pub struct SingleTokenState<AccountId: Eq + Hash + Clone + fmt::Debug> {
    name: String,
    symbol: String,
    decimals: u8,
    total_supply: u128,
    balances: HashMap<AccountId, u128>,
    allowances: HashMap<(AccountId, AccountId), u128>,
    is_paused: bool,
    controlled_access_type: ControlledAccessType,
    controlled_access_role: HashMap<AccountId, bool>,
    minter_role: HashMap<AccountId, bool>,
    moderator_role: HashMap<AccountId, bool>,
    pauser_role: HashMap<AccountId, bool>,
    upgrader_role: HashMap<AccountId, bool>,
}

impl<AccountId: Eq + Hash + Clone + fmt::Debug> SingleTokenState<AccountId> {
    fn new() -> Self {
        SingleTokenState {
            name: String::new(),
            symbol: String::new(),
            decimals: 0,
            total_supply: 0,
            balances: HashMap::new(),
            allowances: HashMap::new(),
            is_paused: false,
            controlled_access_type: ControlledAccessType::Deny,
            controlled_access_role: HashMap::new(),
            minter_role: HashMap::new(),
            moderator_role: HashMap::new(),
            pauser_role: HashMap::new(),
            upgrader_role: HashMap::new(),
        }
    }
}

// Function to hash the message for signing
fn hash_message(msg: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(msg);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}



// Function to recover the public key from the signature
fn ec_recover(
    message_hash: [u8; 32],
    signature: &Signature,
    v: u8,
) -> Result<PublicKey, secp256k1::Error> {
    let secp = Secp256k1::new();
    let recovery_id = RecoveryId::from_i32(i32::from(v - 27)).expect("Invalid recovery id");
    recover(
        &secp,
        &Message::from_slice(&message_hash).unwrap(),
        signature,
        &recovery_id,
    )
}

// Function to validate the signature
fn validate_signature<AccountId: Eq + Hash + Clone + fmt::Debug>(
    signer: &AccountId,
    message: &[u8],
    signature: &Signature,
    v: u8,
    expected_pubkey: &PublicKey,
) -> bool {
    let message_hash = hash_message(message);
    match ec_recover(message_hash, signature, v) {
        Ok(recovered_pubkey) => &recovered_pubkey == expected_pubkey,
        Err(_) => false,
    }
}


// Helper function to serialize Account IDs into bytes
fn serialize_account_id<AccountId: Eq + Hash + Clone + fmt::Debug>(
    account_id: &AccountId,
) -> [u8; 32] {
    // This function should serialize the AccountId into a 32-byte array
    // For simplicity, we'll assume AccountId is a String and use its bytes
    let mut bytes = [0u8; 32];
    let account_bytes = account_id.to_string().as_bytes();
    let len = account_bytes.len().min(32);
    bytes[..len].copy_from_slice(&account_bytes[..len]);
    bytes
}

// Helper function to deserialize Account IDs from bytes
fn deserialize_account_id<AccountId: Eq + Hash + Clone + fmt::Debug>(
    bytes: &[u8],
) -> AccountId {
    // This function should deserialize the bytes into an AccountId
    // For simplicity, we'll assume AccountId is a String
    let s = String::from_utf8_lossy(bytes).trim_end_matches('\0').to_string();
    s.into()
}








// refine1: Validates the signature and generates a 192-byte output
pub fn refine1<AccountId: Eq + Hash + Clone + fmt::Debug>(
    _state: &TokenState<AccountId>,
    message: TokenMessage<AccountId>,
    expected_pubkey: &PublicKey,
) -> [u8; 192] {
    let mut output = [0u8; 192];

    match message {
        TokenMessage::New {
            name,
            symbol,
            decimals,
            initial_supply,
            controlled_access_type,
            automator,
            client,
            default_admin,
            upgrader,
            signature,
        } => {
            // Prepare the message for signature validation
            let message_str = format!(
                "{:?}{:?}{:?}{:?}{:?}{:?}{:?}{:?}",
                name,
                symbol,
                decimals,
                initial_supply,
                controlled_access_type,
                automator,
                client,
                default_admin
            );

            // Validate the signature
            if !validate_signature(
                &default_admin,
                message_str.as_bytes(),
                &signature,
                27,
                expected_pubkey,
            ) {
                panic!("Invalid signature for New message");
            }

            output[0] = 0x01; // Message type indicator for New

            // Generate a new TokenID based on hash of the signature input
            let token_id = generate_token_id(&signature);

            // Include TokenID in output
            output[1..21].copy_from_slice(&token_id);

            // Serialize and include other data
            // Name (32 bytes)
            let name_bytes = name.as_bytes();
            let name_len = name_bytes.len().min(32);
            output[21..53].copy_from_slice(&[0u8; 32]);
            output[21..21 + name_len].copy_from_slice(&name_bytes[..name_len]);

            // Symbol (32 bytes)
            let symbol_bytes = symbol.as_bytes();
            let symbol_len = symbol_bytes.len().min(32);
            output[53..85].copy_from_slice(&[0u8; 32]);
            output[53..53 + symbol_len].copy_from_slice(&symbol_bytes[..symbol_len]);

            // Decimals (1 byte)
            output[85] = decimals;

            // Initial Supply (16 bytes for u128)
            output[86..102].copy_from_slice(&initial_supply.to_be_bytes());

            // Controlled Access Type (1 byte)
            output[102] = match controlled_access_type {
                ControlledAccessType::Deny => 0x00,
                ControlledAccessType::Allow => 0x01,
            };

            // Serialize Account IDs
            // Automator (32 bytes)
            output[103..135].copy_from_slice(&serialize_account_id(&automator));

            // Client (32 bytes)
            output[135..167].copy_from_slice(&serialize_account_id(&client));

            // Default Admin (32 bytes)
            output[167..199].copy_from_slice(&serialize_account_id(&default_admin));

            // Upgrader (32 bytes)
            output[199..231].copy_from_slice(&serialize_account_id(&upgrader));

            // The remaining bytes can be zero or used for additional data
        }

        TokenMessage::Mint {
            token_id,
            to,
            amount,
            signature,
        } => {
            let message_str = format!("{:?}{:?}{:?}", token_id, to, amount);

            if !validate_signature(
                &to,
                message_str.as_bytes(),
                &signature,
                27,
                expected_pubkey,
            ) {
                panic!("Invalid signature for Mint message");
            }

            output[0] = 0x02; // Message type indicator for Mint

            // Include TokenID
            output[1..21].copy_from_slice(&token_id);

            // Serialize 'to' Account ID (32 bytes)
            output[21..53].copy_from_slice(&serialize_account_id(&to));

            // Amount (16 bytes for u128)
            output[53..69].copy_from_slice(&amount.to_be_bytes());

            // The remaining bytes can be zero or used for additional data
        }

        TokenMessage::Burn {
            token_id,
            from,
            amount,
            signature,
        } => {
            let message_str = format!("{:?}{:?}{:?}", token_id, from, amount);

            if !validate_signature(
                &from,
                message_str.as_bytes(),
                &signature,
                27,
                expected_pubkey,
            ) {
                panic!("Invalid signature for Burn message");
            }

            output[0] = 0x03; // Message type indicator for Burn

            // Include TokenID
            output[1..21].copy_from_slice(&token_id);

            // Serialize 'from' Account ID (32 bytes)
            output[21..53].copy_from_slice(&serialize_account_id(&from));

            // Amount (16 bytes for u128)
            output[53..69].copy_from_slice(&amount.to_be_bytes());

            // The remaining bytes can be zero or used for additional data
        }

        TokenMessage::Pause {
            token_id,
            sender,
            signature,
        } => {
            let message_str = format!("{:?}{:?}", token_id, sender);

            if !validate_signature(
                &sender,
                message_str.as_bytes(),
                &signature,
                27,
                expected_pubkey,
            ) {
                panic!("Invalid signature for Pause message");
            }

            output[0] = 0x04; // Message type indicator for Pause

            // Include TokenID
            output[1..21].copy_from_slice(&token_id);

            // Serialize 'sender' Account ID (32 bytes)
            output[21..53].copy_from_slice(&serialize_account_id(&sender));

            // The remaining bytes can be zero or used for additional data
        }

        TokenMessage::Unpause {
            token_id,
            sender,
            signature,
        } => {
            let message_str = format!("{:?}{:?}", token_id, sender);

            if !validate_signature(
                &sender,
                message_str.as_bytes(),
                &signature,
                27,
                expected_pubkey,
            ) {
                panic!("Invalid signature for Unpause message");
            }

            output[0] = 0x05; // Message type indicator for Unpause

            // Include TokenID
            output[1..21].copy_from_slice(&token_id);

            // Serialize 'sender' Account ID (32 bytes)
            output[21..53].copy_from_slice(&serialize_account_id(&sender));

            // The remaining bytes can be zero or used for additional data
        }

        TokenMessage::Transfer {
            token_id,
            from,
            to,
            amount,
            signature,
        } => {
            let message_str = format!("{:?}{:?}{:?}{:?}", token_id, from, to, amount);

            if !validate_signature(
                &from,
                message_str.as_bytes(),
                &signature,
                27,
                expected_pubkey,
            ) {
                panic!("Invalid signature for Transfer message");
            }

            output[0] = 0x06; // Message type indicator for Transfer

            // Include TokenID
            output[1..21].copy_from_slice(&token_id);

            // Serialize 'from' Account ID (32 bytes)
            output[21..53].copy_from_slice(&serialize_account_id(&from));

            // Serialize 'to' Account ID (32 bytes)
            output[53..85].copy_from_slice(&serialize_account_id(&to));

            // Amount (16 bytes for u128)
            output[85..101].copy_from_slice(&amount.to_be_bytes());

            // The remaining bytes can be zero or used for additional data
        }

        TokenMessage::Approve {
            token_id,
            owner,
            spender,
            amount,
            signature,
        } => {
            let message_str = format!("{:?}{:?}{:?}{:?}", token_id, owner, spender, amount);

            if !validate_signature(
                &owner,
                message_str.as_bytes(),
                &signature,
                27,
                expected_pubkey,
            ) {
                panic!("Invalid signature for Approve message");
            }

            output[0] = 0x07; // Message type indicator for Approve

            // Include TokenID
            output[1..21].copy_from_slice(&token_id);

            // Serialize 'owner' Account ID (32 bytes)
            output[21..53].copy_from_slice(&serialize_account_id(&owner));

            // Serialize 'spender' Account ID (32 bytes)
            output[53..85].copy_from_slice(&serialize_account_id(&spender));

            // Amount (16 bytes for u128)
            output[85..101].copy_from_slice(&amount.to_be_bytes());

            // The remaining bytes can be zero or used for additional data
        }

        TokenMessage::Permit {
            token_id,
            owner,
            spender,
            value,
            deadline,
            v,
            r,
            s,
            signature,
        } => {
            let message_str = format!(
                "{:?}{:?}{:?}{:?}{:?}",
                token_id, owner, spender, value, deadline
            );

            if !validate_signature(
                &owner,
                message_str.as_bytes(),
                &signature,
                v,
                expected_pubkey,
            ) {
                panic!("Invalid signature for Permit message");
            }

            output[0] = 0x08; // Message type indicator for Permit

            // Include TokenID
            output[1..21].copy_from_slice(&token_id);

            // Serialize 'owner' Account ID (32 bytes)
            output[21..53].copy_from_slice(&serialize_account_id(&owner));

            // Serialize 'spender' Account ID (32 bytes)
            output[53..85].copy_from_slice(&serialize_account_id(&spender));

            // Value (16 bytes for u128)
            output[85..101].copy_from_slice(&value.to_be_bytes());

            // Deadline (8 bytes for u64)
            output[101..109].copy_from_slice(&deadline.to_be_bytes());

            // v (1 byte)
            output[109] = v;

            // r (32 bytes)
            output[110..142].copy_from_slice(&r);

            // s (32 bytes)
            output[142..174].copy_from_slice(&s);

            // The remaining bytes can be zero or used for additional data
        }
    }

    output
}





// refine2: Full implementation with detailed parsing and state updates
pub fn refine2<AccountId: Eq + Hash + Clone + fmt::Debug>(
    state: &mut TokenState<AccountId>,
    parsed_output: [u8; 192],
) {
    let message_type = parsed_output[0];
    let token_id = {
        let mut id = [0u8; 20];
        id.copy_from_slice(&parsed_output[1..21]);
        id
    };

    // Retrieve or create the SingleTokenState for the given TokenID
    let token_state = state.tokens.entry(token_id).or_insert_with(SingleTokenState::new);

    match message_type {
        0x01 => {
            // Handle the 'New' message
            let name_bytes = &parsed_output[21..53];
            let symbol_bytes = &parsed_output[53..85];
            let decimals = parsed_output[85];
            let initial_supply_bytes = &parsed_output[86..102];
            let automator_bytes = &parsed_output[102..134];
            let client_bytes = &parsed_output[134..166];
            let default_admin_bytes = &parsed_output[166..198];

            let name = String::from_utf8_lossy(name_bytes).trim_end_matches('\0').to_string();
            let symbol = String::from_utf8_lossy(symbol_bytes).trim_end_matches('\0').to_string();
            let initial_supply = u128::from_be_bytes(initial_supply_bytes.try_into().unwrap());
            let automator = deserialize_account_id(automator_bytes);
            let client = deserialize_account_id(client_bytes);
            let default_admin = deserialize_account_id(default_admin_bytes);

            token_state.name = name;
            token_state.symbol = symbol;
            token_state.decimals = decimals;
            token_state.total_supply = initial_supply;

            // Set roles
            token_state.minter_role.insert(automator.clone(), true);
            token_state.moderator_role.insert(automator.clone(), true);
            token_state.pauser_role.insert(automator.clone(), true);
            token_state.upgrader_role.insert(default_admin.clone(), true);
            token_state.controlled_access_role.insert(client.clone(), true);
            token_state.controlled_access_role.insert(default_admin.clone(), true);

            // Set balances
            token_state.balances.insert(default_admin.clone(), initial_supply);
        }
        0x02 => {
            // Handle the 'Mint' message
            let to_bytes = &parsed_output[21..53];
            let amount_bytes = &parsed_output[53..69];
            let to: AccountId = deserialize_account_id(to_bytes);
            let amount = u128::from_be_bytes(amount_bytes.try_into().unwrap());

            // Check minter role
            if !token_state.minter_role.contains_key(&to) {
                panic!("Minter role required");
            }

            // Update balances
            *token_state.balances.entry(to).or_insert(0) += amount;
            token_state.total_supply += amount;
        }
        0x03 => {
            // Handle the 'Burn' message
            let from_bytes = &parsed_output[21..53];
            let amount_bytes = &parsed_output[53..69];
            let from: AccountId = deserialize_account_id(from_bytes);
            let amount = u128::from_be_bytes(amount_bytes.try_into().unwrap());

            let balance = token_state.balances.entry(from.clone()).or_insert(0);
            if *balance < amount {
                panic!("Insufficient balance");
            }
            *balance -= amount;
            token_state.total_supply -= amount;
        }
        0x04 => {
            // Handle the 'Pause' message
            let sender_bytes = &parsed_output[21..53];
            let sender: AccountId = deserialize_account_id(sender_bytes);

            if !token_state.pauser_role.contains_key(&sender) {
                panic!("Pauser role required");
            }
            token_state.is_paused = true;
        }
        0x05 => {
            // Handle the 'Unpause' message
            let sender_bytes = &parsed_output[21..53];
            let sender: AccountId = deserialize_account_id(sender_bytes);

            if !token_state.pauser_role.contains_key(&sender) {
                panic!("Pauser role required");
            }
            token_state.is_paused = false;
        }
        0x06 => {
            // Handle the 'Transfer' message
            let from_bytes = &parsed_output[21..53];
            let to_bytes = &parsed_output[53..85];
            let amount_bytes = &parsed_output[85..101];

            let from: AccountId = deserialize_account_id(from_bytes);
            let to: AccountId = deserialize_account_id(to_bytes);
            let amount = u128::from_be_bytes(amount_bytes.try_into().unwrap());

            if token_state.is_paused {
                panic!("Token is paused");
            }
            if !is_allowed(token_state, &from) || !is_allowed(token_state, &to) {
                panic!("Sender or recipient not allowed");
            }

            let sender_balance = token_state.balances.entry(from.clone()).or_insert(0);
            if *sender_balance < amount {
                panic!("Insufficient balance");
            }

            *sender_balance -= amount;
            *token_state.balances.entry(to).or_insert(0) += amount;
        }
        0x07 => {
            // Handle the 'Approve' message
            let owner_bytes = &parsed_output[21..53];
            let spender_bytes = &parsed_output[53..85];
            let amount_bytes = &parsed_output[85..101];

            let owner: AccountId = deserialize_account_id(owner_bytes);
            let spender: AccountId = deserialize_account_id(spender_bytes);
            let amount = u128::from_be_bytes(amount_bytes.try_into().unwrap());

            if !is_allowed(token_state, &owner) || !is_allowed(token_state, &spender) {
                panic!("Owner or spender not allowed");
            }

            token_state.allowances.insert((owner, spender), amount);
        }
        0x08 => {
            // Handle the 'Permit' message
            let owner_bytes = &parsed_output[21..53];
            let spender_bytes = &parsed_output[53..85];
            let value_bytes = &parsed_output[85..101];

            let owner: AccountId = deserialize_account_id(owner_bytes);
            let spender: AccountId = deserialize_account_id(spender_bytes);
            let value = u128::from_be_bytes(value_bytes.try_into().unwrap());

            if !is_allowed(token_state, &owner) || !is_allowed(token_state, &spender) {
                panic!("Owner or spender not allowed");
            }

            token_state.allowances.insert((owner, spender), value);
        }
        _ => panic!("Unknown message type"),
    }
}

// accumulate: Calls refine1 and then refine2
pub fn accumulate2<AccountId: Eq + Hash + Clone + fmt::Debug>(
    state: &mut TokenState<AccountId>,
    messages: Vec<TokenMessage<AccountId>>,
    expected_pubkey: &PublicKey,
) {
    for message in messages {
        let parsed_output = refine1(state, message, expected_pubkey); // Signature validation and output generation
        refine2(state, parsed_output); // Further validation and state operations
    }
}

// Helper function to generate a new TokenID based on the hash of the signature input
fn generate_token_id(signature: &Signature) -> TokenID {
    let mut hasher = Keccak256::new();
    hasher.update(signature.serialize_compact());
    let result = hasher.finalize();
    let mut token_id = [0u8; 20];
    token_id.copy_from_slice(&result[0..20]);
    token_id
}

// Function to check if an account is allowed (within SingleTokenState)
fn is_allowed<AccountId: Eq + Hash + Clone + fmt::Debug>(
    token_state: &SingleTokenState<AccountId>,
    account: &AccountId,
) -> bool {
    match token_state.controlled_access_type {
        ControlledAccessType::Allow => token_state.controlled_access_role.get(account).is_some(),
        ControlledAccessType::Deny => !token_state.controlled_access_role.get(account).is_some(),
    }
}
