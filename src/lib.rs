use std::ffi::CStr;
use std::ffi::CString;

use std::slice;

mod byte_order;
mod reader;
mod tools;
mod type_size;

use reader::Decoder;
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
        }
        let account_keys = AccountKeys::new(&[], None);
        let stack_height: Option<u32> = None;
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
