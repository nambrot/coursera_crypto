mod padding_oracle;
fn main() {
    let decoded_result = padding_oracle::attack(&"f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4")
        .expect("Fail");
    assert_eq!(
        decoded_result,
        "The Magic Words are Squeamish Ossifrage".to_string()
    );
}


