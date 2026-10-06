/// SmartCard-HSM AID: E8 2B 06 01 04 01 81 C3 1F 02 01
pub const SCHSM_AID: [u8; 11] = [
    0xe8, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xc3, 0x1f, 0x02, 0x01,
];

// APDU 指令
pub const INS_SELECT: u8 = 0xa4;
pub const INS_VERIFY: u8 = 0x20;
pub const INS_GET_DATA: u8 = 0xca;
pub const INS_READ_KEY: u8 = 0xb6;
pub const INS_PSO: u8 = 0x2a;

// 状态字 Status Words
pub const SW_SUCCESS: u16 = 0x9000;
pub const SW_AUTH_FAILED_PREFIX: u16 = 0x63c0; // 63 CX
pub const SW_SECURITY_STATUS_NOT_SATISFIED: u16 = 0x6982;
pub const SW_BLOCKED: u16 = 0x6983;
pub const SW_KEY_NOT_FOUND: u16 = 0x6a88;
