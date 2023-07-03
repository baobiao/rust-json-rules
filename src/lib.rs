use std::ptr::NonNull;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce
};

use base64::{Engine as _, engine::{general_purpose}};
use rand::distributions::{Alphanumeric, DistString};
use redis_module::key::{RedisKey, RedisKeyWritable};

use redis_module::{redis_module, Context, RedisError, RedisResult, RedisString, NextArg, RedisValue, KeyType};
use rule::Rule;
use serde_json::Value;

/// Prefix to be applied to the Redis Hashmap objects added.
const REDISRULE_PREFIX : &str = "REDISRULE:";

/// Hash Field for JSON Rule String.
const REDISRULE_HASHFIELD_RULE : &str = "RULE";

/// Hash Field for Confidential Boolean.
const REDISRULE_HASHFIELD_CONFI : &str = "CONFI";

/// Hash Field for Locked Boolean.
const REDISRULE_HASHFIELD_LOCKED: &str = "LOCKED";

/// Hash Field for Nonce String.
const REDISRULE_HASHFIELD_NONCE : &str = "NONCE";


/// TODO List
/// 1. Externalise the getting of Data Encryption Key.


/// # Description
/// Get only the JSON Rule from Redis Hashmap object by specifying the Rule Index.
/// 
/// ## Input Args
/// - REDISRULE.GET
/// - Rule Index (i32) : This value need to be concatenated to the REDISRULE_PREFIX.
/// 
/// ## Return
/// - JSON representation of the rule.
fn redisrule_getrule(ctx: &Context, args: Vec<RedisString>) -> RedisResult {

    // Expect only two arguments including the first argument which is REDISRULE.GET.
    if args.len() != 2 {
        return Err(RedisError::Str("Usage: REDISRULE.GET RULE#"));
    }

    // Ignore the first argument which is REDISRULE.GET.
    let mut args = args.into_iter().skip(1);

    // Create the RedisString by concatenating the prefix REDISRULE_PREFIX and the Rule Index in the argument.
    let hashkey: RedisString = RedisString::create(NonNull::new(ctx.ctx), format!("{}{}", REDISRULE_PREFIX, args.next_arg()?));

    // Check the read-only Redis Rule.
    let hash: RedisKey = ctx.open_key(&hashkey);
    match check_readonly_key(&hash) {
        Ok(_) => {
            // Get the String value of the Rule from the Hashmap object. We will return the JSON as-is without decryption.
            let rule: Option<RedisString> = hash.hash_get(REDISRULE_HASHFIELD_RULE)?;
            Ok(RedisValue::from(rule))
        }
        Err(err) => {
            Err(err)
        }
    }
}


/// # Description
/// Get only the Confidential JSON Rule from Redis Hashmap object by specifying the Rule Index.
/// 
/// ## Input Args
/// - REDISRULE.GETCONFI
/// - Rule Index (i32) : This value need to be concatenated to the REDISRULE_PREFIX.
/// 
/// ## Return
/// - JSON representation of the rule. If Confi flag is True, then the rule is decrypted. Otherwise rule is returned as-is.
fn redisrule_getconfirule(ctx: &Context, args: Vec<RedisString>) -> RedisResult {

    // Expect only two arguments including the first argument which is REDISRULE.GETCONFI.
    if args.len() != 2 {
        return Err(RedisError::Str("Usage: REDISRULE.GETCONFI RULE#"));
    }

    // Ignore the first argument which is REDISRULE.GETCONFI.
    let mut args = args.into_iter().skip(1);

    // Create the RedisString by concatenating the prefix REDISRULE_PREFIX and the Rule Index in the argument.
    let hashkey: RedisString = RedisString::create(NonNull::new(ctx.ctx), format!("{}{}", REDISRULE_PREFIX, args.next_arg()?));

    let hash: RedisKey = ctx.open_key(&hashkey);

    // Check the read-only Redis Rule.
    match check_readonly_key(&hash) {
        Ok(_) => {
            // Get the String value of the Rule from the Hashmap object.
            let rule: Option<RedisString> = hash.hash_get(REDISRULE_HASHFIELD_RULE)?;

            // Check if the Rule is a Confidential Rule is True. If yes, decrypt the Rule string.
            let confi: Option<RedisString> = hash.hash_get(REDISRULE_HASHFIELD_CONFI)?;

            // If this rule is Confidential.
            if confi.is_some() && confi.unwrap().to_string().to_lowercase() == "true" {
                // Get the Nonce from the Hashmap object and decode from Base64.
                let nonce_redisstring: Option<RedisString> = hash.hash_get(REDISRULE_HASHFIELD_NONCE)?;
                let nonce: Vec<u8> = general_purpose::STANDARD.decode(nonce_redisstring.unwrap().as_slice()).unwrap();

                // Decrypt the Rule.
                let json_rule_enc: &str = rule.clone().unwrap().try_as_str().unwrap();
                // Return the decrypted Rule.
                let dek_str: &str = get_dek().unwrap();
                Ok(RedisValue::from(decrypt(json_rule_enc, dek_str, std::str::from_utf8(&nonce).unwrap()).unwrap()))
            }
            // Else this rule is not confidential.
            else {
                // Return the rule as it is.
                Ok(RedisValue::from(rule))
            }
        }
        Err(err) => {
            Err(err)
        }
    }
}


/// # Description
/// Add or Update the Redis Rule to Redis as a Hashmap object.
/// 
/// ## Input Args
/// 1. REDISRULE.PUT
/// 2. Rule Index (i32) : This value need to be concatenated to the REDISRULE_PREFIX.
/// 3. JSON Rule (String) : This is the minify-ed JSON Rule.
/// 4. TRUE/FALSE : This is the Locked Boolean.
/// 5. TRUE/FALSE : This is the Confidential Boolean (Optional).
/// 
/// ## Return
/// - Ok if successful.
fn redisrule_putrule(ctx: &Context, args: Vec<RedisString>) -> RedisResult {

    // Check input arguments length.
    let arg_len: usize = args.len();
    if arg_len != 5 && arg_len != 4 {
        return Err(RedisError::Str("Usage: REDISRULE.PUT RULE# JSON_RULE(String) LOCKED(TRUE/FALSE) [CONFI(TRUE/FALSE)]"));
    }

    // Ignore the first argument which is REDISRULE.PUT.
    let mut args = args.into_iter().skip(1);

    // Create the Rule Index by concatenating the prefix REDISRULE_PREFIX and the Rule Index in the argument.
    let hashkey: RedisString = RedisString::create(NonNull::new(ctx.ctx), format!("{}{}", REDISRULE_PREFIX, args.next_arg()?));

    // Check if any rules exists in Redis with the same key and if it is locked.
    let hash: RedisKey = ctx.open_key(&hashkey);
    if !hash.is_null() {
        // Get the String value of the LOCKED Flag from the Hashmap object.
        let locked: Option<RedisString> = hash.hash_get(REDISRULE_HASHFIELD_LOCKED)?;
        // Check if the LOCKED flag is true.
        if locked.is_some() && locked.unwrap().to_string().to_lowercase() == "true"  {
            // Return error if there exists a rule with the same ID that and LOCKED flag is True.
            return Err(RedisError::Str("Error: Rule with same ID exists and is locked. Cannot update the rule."));
        }
    }

    // JSON Rule
    let rule_json: &str = args.next_arg()?.try_as_str()?;

    // Locked Flag
    let mut locked_flag: &str = "false";
    if args.next_arg()?.to_string().to_lowercase() == "true" {
        locked_flag = "true";
    }

    // Confidential Flag - If specified.
    let mut confi_flag: bool = false;
    if arg_len == 5 {
        if args.next_arg()?.to_string().to_lowercase() == "true" {
            confi_flag = true;
        }
    }

    // Invoke Redis HMSET command to add the input arguments into Redis Hashmap object.
    if confi_flag {
        // Generate a 12 character random string for Nonce.
        let nonce_string: String = Alphanumeric.sample_string(&mut rand::thread_rng(), 12);
        let nonce: &str = nonce_string.as_str();

        return ctx.call("HMSET", 
        // This branch will encrypt the JSON Rule string.
        &[
            hashkey.try_as_str().unwrap(),
            REDISRULE_HASHFIELD_RULE,
            encrypt(rule_json, get_dek().unwrap(), nonce).unwrap().as_str(),
            REDISRULE_HASHFIELD_LOCKED,
            locked_flag,
            REDISRULE_HASHFIELD_CONFI,
            "true",
            REDISRULE_HASHFIELD_NONCE, // Put the AES Nonce in Base64 format into Hash.
            &general_purpose::STANDARD.encode(nonce)
        ])
    }
    else {
        return ctx.call("HMSET", 
        // This branch will not encrypt the JSON Rule string.
        &[
            hashkey.try_as_str().unwrap(),
            REDISRULE_HASHFIELD_RULE,
            rule_json,
            REDISRULE_HASHFIELD_LOCKED,
            locked_flag,
            REDISRULE_HASHFIELD_CONFI,
            "false"
        ])
    }
}


/// # Description
/// Lock the speciied Redis Rule from being edited or updated. This function is idempotent.
/// 
/// ## Input Args
/// 1. REDISRULE.LOCK
/// 2. Rule Index (i32) : This value need to be concatenated to the REDISRULE_PREFIX.
/// 
/// ## Return
/// - Ok if successful.
fn redisrule_lockrule(ctx: &Context, args: Vec<RedisString>) -> RedisResult {

    // Check input arguments length.
    let arg_len: usize = args.len();
    if arg_len != 2 {
        return Err(RedisError::Str("Usage: REDISRULE.LOCK RULE#"));
    }

    // Ignore the first argument which is REDISRULE.LOCK.
    let mut args = args.into_iter().skip(1);

    // Create the Rule Index by concatenating the prefix REDISRULE_PREFIX and the Rule Index in the argument.
    let hashkey: RedisString = RedisString::create(NonNull::new(ctx.ctx), format!("{}{}", REDISRULE_PREFIX, args.next_arg()?));
    let trueflag: RedisString = RedisString::create(NonNull::new(ctx.ctx), "true");

    // Check if any rules exists in Redis.
    let hash: RedisKey = ctx.open_key(&hashkey);
    match check_readonly_key(&hash) {
        Ok(_) => {
            let hash: RedisKeyWritable = ctx.open_key_writable(&hashkey);
            // Set the Locked Flag to True.
            hash.hash_set(REDISRULE_HASHFIELD_LOCKED, trueflag);
            Ok(RedisValue::from("OK"))
        }
        Err(err) => {
            Err(err)
        }
    }
}


/// # Description
/// Unlock the speciied Redis Rule for editing. This function is idempotent.
/// 
/// ## Input Args
/// 1. REDISRULE.UNLOCK
/// 2. Rule Index (i32) : This value need to be concatenated to the REDISRULE_PREFIX.
/// 
/// ## Return
/// - Ok if successful.
fn redisrule_unlockrule(ctx: &Context, args: Vec<RedisString>) -> RedisResult {

    // Check input arguments length.
    let arg_len: usize = args.len();
    if arg_len != 2 {
        return Err(RedisError::Str("Usage: REDISRULE.UNLOCK RULE#"));
    }

    // Ignore the first argument which is REDISRULE.UNLOCK.
    let mut args = args.into_iter().skip(1);

    // Create the Rule Index by concatenating the prefix REDISRULE_PREFIX and the Rule Index in the argument.
    let hashkey: RedisString = RedisString::create(NonNull::new(ctx.ctx), format!("{}{}", REDISRULE_PREFIX, args.next_arg()?));
    let falseflag: RedisString = RedisString::create(NonNull::new(ctx.ctx), "false");

    // Check if any rules exists in Redis.
    let hash: RedisKey = ctx.open_key(&hashkey);
    match check_readonly_key(&hash) {
        Ok(_) => {
            let hash: RedisKeyWritable = ctx.open_key_writable(&hashkey);
            // Set the Locked Flag to True.
            hash.hash_set(REDISRULE_HASHFIELD_LOCKED, falseflag);
            Ok(RedisValue::from("OK"))
        }
        Err(err) => {
            Err(err)
        }
    }
}


/// # Description
/// Delete the speciied Redis Rule.
/// 
/// ## Input Args
/// 1. REDISRULE.DEL
/// 2. Rule Index (i32) : This value need to be concatenated to the REDISRULE_PREFIX.
/// 
/// ## Return
/// - Ok if successful.
/// - Error if Rule does not exist or is Locked.
fn redisrule_delrule(ctx: &Context, args: Vec<RedisString>) -> RedisResult {
    // Check input arguments length.
    let arg_len: usize = args.len();
    if arg_len != 2 {
        return Err(RedisError::Str("Usage: REDISRULE.DEL RULE#"));
    }

    // Ignore the first argument which is REDISRULE.DEL.
    let mut args = args.into_iter().skip(1);

    // Create the Rule Index by concatenating the prefix REDISRULE_PREFIX and the Rule Index in the argument.
    let hashkey: RedisString = RedisString::create(NonNull::new(ctx.ctx), format!("{}{}", REDISRULE_PREFIX, args.next_arg()?));

    // Check if any rules exists in Redis.
    let hash: RedisKey = ctx.open_key(&hashkey);
    match check_readonly_key(&hash) {
        Ok(_) => {
            // Check if the LOCKED flag is true.
            let locked: Option<RedisString> = hash.hash_get(REDISRULE_HASHFIELD_LOCKED)?;
            if locked.is_some() && locked.unwrap().to_string().to_lowercase() == "true"  {
                // Return error if there exists a rule with the same ID that and LOCKED flag is True.
                return Err(RedisError::Str("Error: Rule with same ID is locked. Cannot delete the rule."));
            }
            let hash: RedisKeyWritable = ctx.open_key_writable(&hashkey);
            return hash.delete();
        }
        Err(err) => {
            Err(err)
        }
    }
}



/// # Description
/// Evaluate a JSON against the specified Rule ID.
/// 
/// ## Input Args
/// 1. REDISRULE.EVAL
/// 2. Rule Index (i32) : This value need to be concatenated to the REDISRULE_PREFIX.
/// 3. JSON String : This is the minified JSON string that needs to be evaluated using the rule.
/// 
/// ## Return
/// - 1 if Rule evaluation Pass.  0 if Rule evaluation Fail.
/// - Error if Rule does not exist.
fn redisrule_evalrule(ctx: &Context, args: Vec<RedisString>) -> RedisResult {

    // Check input arguments length.
    let arg_len: usize = args.len();
    if arg_len != 3 {
        return Err(RedisError::Str("Usage: REDISRULE.EVAL RULE# JSON_INPUT"));
    }

    // Ignore the first argument which is REDISRULE.EVAL.
    let mut args = args.into_iter().skip(1);

    // Create the Rule Index by concatenating the prefix REDISRULE_PREFIX and the Rule Index in the argument.
    let hashkey: RedisString = RedisString::create(NonNull::new(ctx.ctx), format!("{}{}", REDISRULE_PREFIX, args.next_arg()?));

    // Check if any rules exists in Redis.
    let hash: RedisKey = ctx.open_key(&hashkey);
    match check_readonly_key(&hash) {
        Ok(_) => {
            // Get the String value of the Rule from the Hashmap object.
            let rule: Option<RedisString> = hash.hash_get(REDISRULE_HASHFIELD_RULE)?;

            // Check if the Rule is a Confidential Rule is True. If yes, decrypt the Rule string.
            let confi: Option<RedisString> = hash.hash_get(REDISRULE_HASHFIELD_CONFI)?;

            // If this rule is Confidential.
            if confi.is_some() && confi.unwrap().to_string().to_lowercase() == "true" {
                // Get the Nonce from the Hashmap object and decode from Base64.
                let nonce_redisstring: Option<RedisString> = hash.hash_get(REDISRULE_HASHFIELD_NONCE)?;
                let nonce: Vec<u8> = general_purpose::STANDARD.decode(nonce_redisstring.unwrap().as_slice()).unwrap();

                // Decrypt the Rule.
                let json_rule_enc: &str = rule.clone().unwrap().try_as_str().unwrap();
                let dek_str: &str = get_dek().unwrap();
                let rule: String = decrypt(json_rule_enc, dek_str, std::str::from_utf8(&nonce).unwrap()).unwrap();

                // Evaluate the rule.
                let input_json: Value = serde_json::from_str((args.next_arg()?).to_string().as_str())?;
                let rulejson: Value = serde_json::from_str(&rule)?;
                return evaluate_rule(&Rule::new(rulejson).unwrap(), input_json);
            }
            // Else this rule is not confidential.
            else {
                // Evaluate the rule.
                let input_json: Value = serde_json::from_str((args.next_arg()?).to_string().as_str())?;
                let rulejson: Value = serde_json::from_str(rule.unwrap().to_string().as_str())?;
                let r: Rule = match Rule::new(rulejson) {
                    Ok(r) => r,
                    Err(err) => {
                        return Err(RedisError::String(format!("Error: {:?}", err)))
                    }
                };
                return evaluate_rule(&r, input_json);
            }
        }
        Err(err) => {
            Err(err)
        }
    }
} 



//////////////////////////////////////////////////////

redis_module! {
    name: "redisrule",
    version: 1,
    allocator: (redis_module::alloc::RedisAlloc, redis_module::alloc::RedisAlloc),
    data_types: [],
    commands: [
        ["REDISRULE.GET",       redisrule_getrule,      "",         0, 0, 0],
        ["REDISRULE.GETCONFI",  redisrule_getconfirule, "",         0, 0, 0],
        ["REDISRULE.LOCK",      redisrule_lockrule,     "write",    0, 0, 0],
        ["REDISRULE.UNLOCK",    redisrule_unlockrule,   "write",    0, 0, 0],
        ["REDISRULE.DEL",       redisrule_delrule,      "write",    0, 0, 0],
        ["REDISRULE.PUT",       redisrule_putrule,      "write",    0, 0, 0],
        ["REDISRULE.EVAL",      redisrule_evalrule,     "",         0, 0, 0],
    ],
}


/// # Description
/// Does common checks on Read-only Redis Key.
/// 
/// ## Input
/// 1. Hash - RedisKey reference.
/// 
/// ## Output
/// Ok - If checks pass.
/// Error if checks fail.
fn check_readonly_key(hash: &RedisKey) -> RedisResult {

    // Check if the Rule ID exists.
    if hash.is_null() {
        return Err(RedisError::Str("Error: Rule ID does not exist."));
    }

    // Check if the type of Redis object returned is Hash.
    let key_type: KeyType = hash.key_type();
    if key_type != KeyType::Hash {
        return Err(RedisError::Str("Error: Rule ID does not point to a Redis Hash object."));
    }

    return Ok(RedisValue::Bool(true))
}


/// # Description
/// Encrypt the input string using the provided data encryption key (DEKm).
/// 
/// ## Input Args
/// 1. json_str (&str) : This is the string representing the JSON.
/// 2. dek (&str) : This is the data encryption key.
/// 3. nonce (&str) : This is the 12 character Nonce.
/// 
/// ## Return
/// - String - Encrypted String in Base64 encoding.
/// - Error - If any error occurs.
fn encrypt(json_str: &str, dek: &str, nonce: &str) -> Result<String, RedisError> {
    let key = Key::<Aes256Gcm>::from_slice(dek.as_bytes());
    let cipher = Aes256Gcm::new(&key);
    match cipher.encrypt(nonce.as_bytes().into(), json_str.as_bytes()) {
        Ok(response) => {
            Ok(general_purpose::STANDARD.encode(response))
        }
        Err(err) => {
            Err(RedisError::String(format!("Error: {}", err)))
        }
    }
}


/// # Description
/// Decrypt the input string using the provided data encryption key (DEK).
/// 
/// ## Input Args
/// 1. encrypted_str (&str) : This is the string representing the Encrypted String in Base64 encoding.
/// 2. dek (&str) : This is the data encryption key.
/// 3. nonce (&str) : This is the 12 character Nonce.
/// 
/// ## Return
/// - String - Decrypted String in original text.
/// - Error - If any error occurs.
fn decrypt(encrypted_str: &str, dek: &str, nonce: &str) -> Result<String, RedisError> {
    let key = Key::<Aes256Gcm>::from_slice(dek.as_bytes());
    let cipher = Aes256Gcm::new(&key);
    let nonce_c = Nonce::from_slice(nonce.as_bytes());
    let decoded_str = general_purpose::STANDARD.decode(encrypted_str).unwrap();
    match cipher.decrypt(nonce_c, decoded_str.as_slice()) {
        Ok(plaintext) => {
            Ok(String::from_utf8(plaintext).unwrap())
        }
        Err(err) => {
            Err(RedisError::String(format!("Error: {}", err)))
        }
    }
}

/// # Description
/// Evaluate the Rule and return the boolean result.
/// 
/// ## Input Args
/// 1. rule (&Rule) : This is the Rule object.
/// 2. input_json (Value) : This is the JSON object.
/// 
/// ## Return
/// - bool - Result of the evaluation. TRUE if rule evaluate pass, FALSE if rule evaluate fail.
fn evaluate_rule(rule: &Rule, input_json: Value) -> RedisResult {
    // Evaluate the rule.
    match rule.matches(&input_json) {
        Ok(val) => {
            return Ok(RedisValue::Bool(val))
        }
        Err(err) => {
            return Err(RedisError::String(format!("Error: {:?}", err)))
        }
    }
}


/// # Description
/// Fetch the Data Encryption Key from an external secure source.
/// 
/// ## Input Args
/// Nil
/// 
/// ## Return
/// - str - Data Encryption Key.
fn get_dek() -> Result<&'static str, RedisError> {
    //TODO: Externalise the getting of Data Encryption Key.
    // CHANGEME to a 32 character string.
    Ok("12345678901234567890123456789012")
}