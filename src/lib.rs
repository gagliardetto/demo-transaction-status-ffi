use std::ffi::CStr;
use std::ffi::CString;

use std::slice;

mod byte_order;
mod reader;
mod tools;
mod type_size;

use reader::Decoder;
use reader::Error;
use solana_sdk::message::v0::LoadedAddresses;
use solana_sdk::{
    instruction::CompiledInstruction, message::AccountKeys, pubkey::Pubkey, stake, system_program,
    vote,
};
use solana_transaction_status::parse_instruction::parse;

#[no_mangle]
pub extern "C" fn hello_from_rust() {
    println!("Hello from Rust at time: {}!", chrono::Local::now());
}

#[no_mangle]
pub extern "C" fn parse_instruction(bytes: *const u8, len: usize) -> Response {
    let bytes = unsafe {
        assert!(!bytes.is_null());
        slice::from_raw_parts(bytes, len)
    };
    let bytes = bytes.to_vec();
    println!("[rust] params raw bytes: {:?}", bytes);
    let mut decoder = Decoder::new(bytes);
    {
        // read program ID:
        let program_id_bytes = decoder.read_bytes(32).unwrap();
        let program_id = solana_sdk::pubkey::Pubkey::new(&program_id_bytes);
        println!("[rust] program_id: {:?}", program_id,);
        let mut instruction = CompiledInstruction {
            program_id_index: 0,
            accounts: vec![],
            data: vec![],
        };
        {
            instruction.program_id_index = decoder.read_u8().unwrap() as u8;
            println!(
                "[rust] program_id_index: {:?}",
                instruction.program_id_index
            );
            let accounts_len = decoder.read_u8().unwrap() as usize;
            println!("[rust] accounts_len: {:?}", accounts_len);
            for _ in 0..accounts_len {
                let account_index = decoder.read_u8().unwrap() as u8;
                println!("[rust] account_index: {:?}", account_index);
                instruction.accounts.push(account_index);
            }
            let data_len = decoder.read_u8().unwrap() as usize;
            println!("[rust] data_len: {:?}", data_len);
            for _ in 0..data_len {
                let data_byte = decoder.read_u8().unwrap() as u8;
                println!("[rust] data_byte: {:?}", data_byte);
                instruction.data.push(data_byte);
            }
        }

        let parsed = parse_accountkeys(decoder).unwrap();
        let mut stuff = &parsed.child.unwrap();
        let account_keys = AccountKeys::new(&parsed.parent, Some(stuff));

        let mut stack_height: Option<u32> = None;
        let parsed = parse(
            &program_id, // program_id
            &instruction,
            &account_keys,
            stack_height,
        );
        _ = parsed;
    }
    let mut response = vec![0; 32];
    for i in 0..32 {
        response[i] = i as u8;
    }
    let data = response.as_mut_ptr();
    let len = response.len();
    std::mem::forget(response);
    Response {
        buf: Buffer { data, len },
        status: 123,
    }
}

#[repr(C)]
struct Response {
    buf: Buffer,
    status: i32,
}

#[repr(C)]
struct Buffer {
    data: *mut u8,
    len: usize,
}

extern "C" fn free_buf(buf: Buffer) {
    let s = unsafe { std::slice::from_raw_parts_mut(buf.data, buf.len) };
    let s = s.as_mut_ptr();
    unsafe {
        Box::from_raw(s);
    }
}

// write a C external function that accepts a string, parses it as json, and returns a string:
#[no_mangle]
pub extern "C" fn accept_json(json: *const libc::c_char) -> *const libc::c_char {
    let json = unsafe { CStr::from_ptr(json).to_bytes() };
    let json = String::from_utf8(json.to_vec()).unwrap();
    {
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        println!("v: {:?}", v);
    }
    let json = json + "!";
    let json = CString::new(json).unwrap().into_raw();
    json
}

pub fn parse_accountkeys<'a>(mut decoder: Decoder) -> Result<Combined, Error> {
    let static_account_keys_len = decoder.read_u8().unwrap() as usize;
    println!(
        "[rust] static_account_keys_len: {:?}",
        static_account_keys_len
    );
    let mut static_account_keys_vec = vec![];
    for _ in 0..static_account_keys_len {
        let account_key_bytes = decoder.read_bytes(32).unwrap();
        let account_key = solana_sdk::pubkey::Pubkey::new(&account_key_bytes);
        println!("[rust] account_key: {:?}", account_key);
        static_account_keys_vec.push(account_key);
    }

    let has_dynamic_account_keys = decoder.read_option().unwrap();
    println!(
        "[rust] has_dynamic_account_keys: {:?}",
        has_dynamic_account_keys
    );
    if has_dynamic_account_keys {
        let mut loaded_addresses = LoadedAddresses::default();
        let num_writable_accounts = decoder.read_u8().unwrap() as usize;
        println!("[rust] num_writable_accounts: {:?}", num_writable_accounts);
        // read 32 bytes for each writable account:
        for _ in 0..num_writable_accounts {
            let account_key_bytes = decoder.read_bytes(32).unwrap();
            let account_key = solana_sdk::pubkey::Pubkey::new(&account_key_bytes);
            println!("[rust] account_key: {:?}", account_key);
            loaded_addresses.writable.push(account_key);
        }
        let num_readonly_accounts = decoder.read_u8().unwrap() as usize;
        println!("[rust] num_readonly_accounts: {:?}", num_readonly_accounts);
        // read 32 bytes for each readonly account:
        for _ in 0..num_readonly_accounts {
            let account_key_bytes = decoder.read_bytes(32).unwrap();
            let account_key = solana_sdk::pubkey::Pubkey::new(&account_key_bytes);
            println!("[rust] account_key: {:?}", account_key);
            loaded_addresses.readonly.push(account_key);
        }

        return Ok(Combined {
            parent: static_account_keys_vec,
            child: Some(loaded_addresses),
        });
    } else {
        return Ok(Combined {
            parent: static_account_keys_vec,
            child: None,
        });
    }
}
struct Combined {
    parent: Vec<Pubkey>,
    child: Option<LoadedAddresses>,
}
