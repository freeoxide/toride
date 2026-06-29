use super::parse_serials;

// ---------------------------------------------------------------------------
// Workflow-discovered edge cases: KRL serial range OOM
// ---------------------------------------------------------------------------

#[test]
fn parse_serials_normal_range() {
    let mut out = Vec::new();
    parse_serials("1-5", &mut out);
    assert_eq!(out, vec![1, 2, 3, 4, 5]);
}

#[test]
fn parse_serials_single_number() {
    let mut out = Vec::new();
    parse_serials("42", &mut out);
    assert_eq!(out, vec![42]);
}

#[test]
fn parse_serials_reversed_range_ignored() {
    let mut out = Vec::new();
    parse_serials("10-5", &mut out);
    // Reversed range should be ignored
    assert!(out.is_empty());
}

#[test]
fn parse_serials_huge_range_capped() {
    // This would OOM without the cap fix
    let mut out = Vec::new();
    parse_serials("0-999999999", &mut out);
    // Should be capped at MAX_SERIAL_RANGE_EXPANSION (10000)
    assert!(
        out.len() <= 10_000,
        "serial range should be capped, got {}",
        out.len()
    );
}

#[test]
fn parse_serials_exact_cap_boundary() {
    let mut out = Vec::new();
    parse_serials("0-9999", &mut out);
    // 10000 entries is exactly at the cap
    assert_eq!(out.len(), 10_000);
}

#[test]
fn parse_serials_just_over_cap() {
    let mut out = Vec::new();
    parse_serials("0-10000", &mut out);
    // 10001 entries is just over the cap, should be capped
    assert_eq!(out.len(), 10_000);
}

#[test]
fn parse_serials_empty_input() {
    let mut out = Vec::new();
    parse_serials("", &mut out);
    assert!(out.is_empty());
}

#[test]
fn parse_serials_whitespace_only() {
    let mut out = Vec::new();
    parse_serials("   ", &mut out);
    assert!(out.is_empty());
}

#[test]
fn parse_serials_range_with_spaces() {
    let mut out = Vec::new();
    parse_serials(" 1 - 5 ", &mut out);
    assert_eq!(out, vec![1, 2, 3, 4, 5]);
}

#[test]
fn parse_serials_non_numeric() {
    let mut out = Vec::new();
    parse_serials("abc", &mut out);
    assert!(out.is_empty());
}

#[test]
fn parse_serials_range_non_numeric() {
    let mut out = Vec::new();
    parse_serials("abc-def", &mut out);
    assert!(out.is_empty());
}

#[test]
fn parse_serials_range_mixed_numeric() {
    let mut out = Vec::new();
    parse_serials("1-abc", &mut out);
    assert!(out.is_empty());
}

#[test]
fn parse_serials_zero_range() {
    let mut out = Vec::new();
    parse_serials("5-5", &mut out);
    assert_eq!(out, vec![5]);
}
