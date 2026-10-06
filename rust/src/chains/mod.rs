pub mod eth;
pub mod tron;

pub use eth::*;
pub use tron::*;

use anyhow::{anyhow, Result};

/// 解析用户输入的金额字符串（支持小数），转换为最小单位整数
///
/// decimals: 小数位数 (ETH=18, USDT=6, TRX=6)
/// 拒绝负数、空串、非数字、前导零（"01.0"）、超过精度的小数位
pub fn parse_amount(input: &str, decimals: u8) -> Result<u128> {
    let s = input.trim();
    if s.is_empty() {
        return Err(anyhow!("请输入金额"));
    }
    if s.starts_with('-') {
        return Err(anyhow!("金额不能为负数"));
    }
    if s.starts_with('0') && s.len() > 1 && s.chars().nth(1) != Some('.') {
        return Err(anyhow!("金额格式错误：不允许前导零"));
    }

    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() > 2 {
        return Err(anyhow!("金额格式错误：多个小数点"));
    }

    let integer_part = parts[0];
    if !integer_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(anyhow!("金额包含非法字符"));
    }

    let mut result_str = integer_part.to_string();

    if parts.len() == 2 {
        let frac = parts[1];
        if frac.len() > decimals as usize {
            return Err(anyhow!("小数位超过 {} 位精度", decimals));
        }
        if !frac.chars().all(|c| c.is_ascii_digit()) {
            return Err(anyhow!("小数部分包含非法字符"));
        }
        result_str.push_str(frac);
        result_str.push_str(&"0".repeat(decimals as usize - frac.len()));
    } else {
        result_str.push_str(&"0".repeat(decimals as usize));
    }

    let value = result_str
        .parse::<u128>()
        .map_err(|_| anyhow!("金额格式错误或超出范围"))?;
    if value == 0 {
        return Err(anyhow!("金额必须大于 0"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_amount() {
        assert_eq!(parse_amount("1", 6).unwrap(), 1_000_000);
        assert_eq!(parse_amount("0.1", 6).unwrap(), 100_000);
        assert_eq!(parse_amount("10.5", 6).unwrap(), 10_500_000);
        assert_eq!(parse_amount("0.000001", 6).unwrap(), 1);

        assert_eq!(parse_amount("1.", 6).unwrap(), 1_000_000);
        assert_eq!(parse_amount("0.000000000000000001", 18).unwrap(), 1);
        assert!(parse_amount("0", 6).is_err());
        assert!(parse_amount("0.000", 6).is_err());
        assert!(parse_amount(".", 6).is_err());
        assert!(parse_amount("1e5", 6).is_err());
        assert!(parse_amount("1,5", 6).is_err());
        assert!(parse_amount("", 6).is_err());
        assert!(parse_amount("-1", 6).is_err());
        assert!(parse_amount("01.5", 6).is_err());
        assert!(parse_amount("1.0000001", 6).is_err());
    }
}
