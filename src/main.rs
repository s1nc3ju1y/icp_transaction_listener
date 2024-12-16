use candid::{types::result, CandidType, Decode, Encode};
use ic_agent::{export::Principal, Agent};
use serde::Deserialize;
use std::{env, error::Error, os::unix::thread, vec};
use tokio::time::{sleep, Duration};

use crc::{Crc, CRC_32_ISO_HDLC};
use hex;

#[derive(CandidType)]
struct GetBlocksArgs {
    start: u64,
    length: u64,
}

#[derive(CandidType, Deserialize, Debug)]
struct Tokens {
    e8s: u64,
}

#[derive(CandidType, Deserialize, Debug)]
struct QueryBlocksResponse {
    chain_length: u64,
    certificate: Option<Vec<u8>>,
    blocks: Vec<Block>,
    first_block_index: u64,
    archived_blocks: Vec<ArchivedBlocksRange>,
}

#[derive(CandidType, Deserialize, Debug)]
struct Block {
    parent_hash: Option<Vec<u8>>,
    transaction: Transaction,
    timestamp: TimeStamp,
}

#[derive(CandidType, Deserialize, Debug)]
struct Transaction {
    memo: u64,
    icrc1_memo: Option<Vec<u8>>,
    operation: Option<Operation>,
    created_at_time: TimeStamp,
}

#[derive(CandidType, Deserialize, Debug)]
struct TimeStamp {
    timestamp_nanos: u64,
}

#[derive(CandidType, Deserialize, Debug)]
enum Operation {
    Mint {
        to: Vec<u8>,
        amount: Tokens,
    },
    Burn {
        from: Vec<u8>,
        spender: Option<Vec<u8>>,
        amount: Tokens,
    },
    Transfer {
        from: Vec<u8>,
        to: Vec<u8>,
        amount: Tokens,
        fee: Tokens,
        spender: Option<Vec<u8>>,
    },
}

#[derive(CandidType, Deserialize, Debug)]
struct ArchivedBlocksRange {
    start: u64,
    length: u64,
    callback: String, // Simulated, actual callback function not implemented in Rust here
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        panic!("Usage: {} <ICP Address>", args[0])
    }

    let address = &args[1];
    // 轮询间隔10秒
    let sleep_duration = Duration::from_secs(3);
    match validate_icp_address(address) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Error: {}", e);
            panic!("Address invalid");
        }
    }

    let black_list = vec![address.clone()];

    let url = "http://127.0.0.1:4943/";
    let agent = Agent::builder().with_url(url).build()?;
    // Only do the following call when not contacting the IC main net (e.g. a local emulator).
    // This is important as the main net public key is static and a rogue network could return
    // a different key.
    // If you know the root key ahead of time, you can use `agent.set_root_key(root_key);`.
    agent.fetch_root_key().await?;
    // 目标 Canister ID
    let canister_id = Principal::from_text("ryjl3-tyaaa-aaaaa-aaaba-cai")?;

    for start in 0..10u64 {
        println!("Fetching tx...");

        // 构造请求参数
        let get_blocks_args = GetBlocksArgs {
            start: start,
            length: 1,
        };

        // 序列化参数
        let args = Encode!(&get_blocks_args)?;

        // 调用 Canister 的 query_blocks 方法
        let response = agent
            .query(&canister_id, "query_blocks")
            .with_arg(args) // 直接传入序列化后的参数
            .call()
            .await?;

        // 解析返回值
        let result: QueryBlocksResponse = Decode!(&response, QueryBlocksResponse)?;
        // println!("QueryBlocksResponse: {:?}", result);
        for block in result.blocks {
            if let Some(Operation::Transfer {
                from, to, amount, ..
            }) = block.transaction.operation
            {
                let from_address = to_icp_address(&from);
                let to_address = to_icp_address(&to);
                if black_list.contains(&from_address) || black_list.contains(&to_address) {
                    println!("Sanction address tx found!");
                    println!(
                        "From: {}, To: {}, Operation: Transfer, Amount: {}",
                        from_address, to_address, amount.e8s
                    )
                }
            }
        }

        sleep(sleep_duration).await;
    }

    Ok(())
}

fn get_block_list() -> Vec<String> {
    let list = vec!["e6197b5ed6c67e547118a44e043d5f54b1e7388bab76733dddc59c0e56ec229c".to_string()];
    list
}

// 转换为 ICP 地址的函数
fn to_icp_address(raw_bytes: &Vec<u8>) -> String {
    // Define the CRC32 checksum calculator
    let crc32 = Crc::<u32>::new(&CRC_32_ISO_HDLC);

    // Compute CRC32 checksum for the last 28 bytes
    let checksum = crc32.checksum(&raw_bytes[4..]);
    // Convert checksum to big-endian bytes
    let checksum_bytes = checksum.to_be_bytes();

    // Combine checksum and last 28 bytes
    let mut address = Vec::new();
    address.extend_from_slice(&checksum_bytes);
    address.extend_from_slice(&raw_bytes[4..]);

    // Convert to hex string
    hex::encode(address)
}

fn validate_icp_address(address: &str) -> Result<(), Box<dyn Error>> {
    // ICP addresses should be 64-character hex strings
    if address.len() != 64 {
        return Err("Invalid address length: ICP address must be 64 characters.".into());
    }

    // Convert the address from hex string to bytes
    let address_bytes = hex::decode(address).map_err(|_| "Invalid hex string format.")?;

    // Ensure the address is exactly 32 bytes
    if address_bytes.len() != 32 {
        return Err("Invalid address length: ICP address must be 32 bytes after decoding.".into());
    }

    // Extract the checksum and the data
    let provided_checksum = &address_bytes[0..4];
    let data_bytes = &address_bytes[4..];

    // Calculate the CRC32 checksum of the data bytes
    let crc32 = Crc::<u32>::new(&CRC_32_ISO_HDLC);
    let calculated_checksum = crc32.checksum(data_bytes);

    // Compare the provided checksum with the calculated checksum
    if provided_checksum != &calculated_checksum.to_be_bytes() {
        return Err("Checksum validation failed: The provided checksum is incorrect.".into());
    }

    Ok(())
}
