use base64;
use console::style;
use lazy_static::lazy_static;
use percent_encoding::percent_decode_str;
use regex::{Captures, Regex};
use std::borrow::Cow;

lazy_static! {
    pub static ref RE: Regex = Regex::new(r"^igmobileotp://\?(?P<payload>action=secactivate&enc=(?P<salt>(?:[a-zA-Z0-9/+]|%2[bBfF]){12})(?P<enc_rest>(?:[a-zA-Z0-9/+]|%2[bBfF])*)&v=1)&mac=(?P<mac>(?:[a-zA-Z0-9/+=]|%2[bBfF]|%3[dD]){16})$").unwrap();
}

pub fn get_salt(c: &Captures) -> [u8; 8] {
    let mut res = [0; 9];
    let percent_dec: Cow<[u8]> = percent_decode_str(&c["salt"]).into();
    base64::decode_config_slice(&percent_dec, base64::STANDARD_NO_PAD, &mut res).unwrap();
    let mut res_8 = [0; 8];
    res_8.copy_from_slice(&res[0..8]);
    res_8
}

pub fn get_mac(c: &Captures) -> [u8; 12] {
    let mut res = [0; 12];
    let percent_dec: Cow<[u8]> = percent_decode_str(&c["mac"]).into();
    base64::decode_config_slice(&percent_dec, base64::STANDARD_NO_PAD, &mut res).unwrap();
    res
}

pub fn visualise_url(caps: &Captures) {
    let enc_trunc = format!(
        "{}...{}",
        &caps["enc_rest"][..5],
        &caps["enc_rest"][caps["enc_rest"].len() - 5..]
    );

    let printed_parts = [
        style("igmobileotp://").white(),
        style("?action=secactivate&enc=").cyan(),
        style(&caps["salt"]).cyan().bold(),
        style(&*enc_trunc).cyan(),
        style("&v=1").cyan(),
        style("&mac=").white(),
        style(&caps["mac"]).magenta(),
    ];

    print!("    ");
    for part in &printed_parts {
        print!("{}", part);
    }
    print!("\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deconstructs_sample_url() {
        let caps = RE.captures("igmobileotp://?action=secactivate&enc=VRUq6IoLWQRCMRITZEHtHUSWJiPwgu%2FN1BFyUHE5kxuHIEYoE3zmNTrAHeeUM5S3gzCnTy%2F%2Bdnbu%2FsjjQW%2BNEISx8C4ra8rLpxOl8E8w4KXHgjeBRgdvSzl%2BbzX5RYRrQlWgK8hsBT4pQYE0eFgW2TmRbzXu1Mu7XjKDcwsJLew32jQC2qyPLP8hljnv2rHwwsMfhQwgJUJYfctwLWWEDUFukEckaZ4O&v=1&mac=mhVL8BWKaishMa5%2B").unwrap();

        assert_eq!(
            &caps["payload"],
            "action=secactivate&enc=VRUq6IoLWQRCMRITZEHtHUSWJiPwgu%2FN1BFyUHE5kxuHIEYoE3zmNTrAHeeUM5S3gzCnTy%2F%2Bdnbu%2FsjjQW%2BNEISx8C4ra8rLpxOl8E8w4KXHgjeBRgdvSzl%2BbzX5RYRrQlWgK8hsBT4pQYE0eFgW2TmRbzXu1Mu7XjKDcwsJLew32jQC2qyPLP8hljnv2rHwwsMfhQwgJUJYfctwLWWEDUFukEckaZ4O&v=1"
        );

        assert_eq!(
            get_salt(&caps),
            [0x55, 0x15, 0x2a, 0xe8, 0x8a, 0x0b, 0x59, 0x04]
        );
        assert_eq!(get_mac(&caps), *b"\x9a\x15K\xf0\x15\x8aj+!1\xae~");
    }
}
