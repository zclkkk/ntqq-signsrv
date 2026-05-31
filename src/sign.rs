pub struct SignOutput {
    pub sign: Vec<u8>,
    pub token: Vec<u8>,
    pub extra: Vec<u8>,
}

pub fn parse_output(buf: &[u8; 768]) -> SignOutput {
    let token_len = buf[0xFF] as usize;
    let extra_len = buf[0x1FF] as usize;
    let sign_len = buf[0x2FF] as usize;

    SignOutput {
        sign: buf[0x200..0x200 + sign_len].to_vec(),
        token: buf[0x000..0x000 + token_len].to_vec(),
        extra: buf[0x100..0x100 + extra_len].to_vec(),
    }
}
