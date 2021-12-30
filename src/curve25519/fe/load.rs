pub(crate) const fn load_4u(s: &[u8]) -> u64 {
    (s[0] as u64) | ((s[1] as u64) << 8) | ((s[2] as u64) << 16) | ((s[3] as u64) << 24)
}
pub(crate) const fn load_4i(s: &[u8]) -> i64 {
    load_4u(s) as i64
}
pub(crate) const fn load_3u(s: &[u8]) -> u64 {
    (s[0] as u64) | ((s[1] as u64) << 8) | ((s[2] as u64) << 16)
}
pub(crate) const fn load_3i(s: &[u8]) -> i64 {
    load_3u(s) as i64
}
