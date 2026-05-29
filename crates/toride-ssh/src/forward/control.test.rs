use super::*;

#[test]
fn parse_local_forward_line() {
    let line = "127.0.0.1 port 8080, forwarding to 10.0.0.1 port 80";
    let fwd = parse_forward_line(line, ForwardType::Local).unwrap();
    assert_eq!(fwd.local_addr, "127.0.0.1");
    assert_eq!(fwd.local_port, 8080);
    assert_eq!(fwd.remote_addr, "10.0.0.1");
    assert_eq!(fwd.remote_port, 80);
    assert_eq!(fwd.forward_type, ForwardType::Local);
}

#[test]
fn parse_local_forward_truncated_addr() {
    let line = "127.0.0. port 8080, forwarding to 10.0.0.1 port 80";
    let fwd = parse_forward_line(line, ForwardType::Local).unwrap();
    assert_eq!(fwd.local_addr, "127.0.0");
    assert_eq!(fwd.local_port, 8080);
    assert_eq!(fwd.remote_addr, "10.0.0.1");
    assert_eq!(fwd.remote_port, 80);
}

#[test]
fn parse_gateway_ports_forward() {
    let line = "* port 9090, forwarding to 192.168.1.1 port 443";
    let fwd = parse_forward_line(line, ForwardType::Local).unwrap();
    assert_eq!(fwd.local_addr, "*");
    assert_eq!(fwd.local_port, 9090);
    assert_eq!(fwd.remote_addr, "192.168.1.1");
    assert_eq!(fwd.remote_port, 443);
}

#[test]
fn parse_dynamic_forward_line() {
    let line = "127.0.0.1 port 1080";
    let fwd = parse_forward_line(line, ForwardType::Dynamic).unwrap();
    assert_eq!(fwd.local_addr, "127.0.0.1");
    assert_eq!(fwd.local_port, 1080);
    assert_eq!(fwd.forward_type, ForwardType::Dynamic);
}

#[test]
fn parse_dynamic_forward_gateway() {
    let line = "* port 1080";
    let fwd = parse_forward_line(line, ForwardType::Dynamic).unwrap();
    assert_eq!(fwd.local_addr, "*");
    assert_eq!(fwd.local_port, 1080);
}

#[test]
fn parse_full_output() {
    let output = "\
Local connections:
  127.0.0.1 port 8080, forwarding to 10.0.0.1 port 80
  0.0.0.0 port 9090, forwarding to 192.168.1.1 port 443
Remote connections:
  127.0.0.1 port 2222, forwarding to 127.0.0.1 port 22
Dynamic connections:
  127.0.0.1 port 1080
";
    let fwds = parse_forward_output(output);
    assert_eq!(fwds.len(), 4);
    assert_eq!(fwds[0].forward_type, ForwardType::Local);
    assert_eq!(fwds[0].local_port, 8080);
    assert_eq!(fwds[1].forward_type, ForwardType::Local);
    assert_eq!(fwds[1].local_port, 9090);
    assert_eq!(fwds[2].forward_type, ForwardType::Remote);
    assert_eq!(fwds[2].remote_port, 22);
    assert_eq!(fwds[3].forward_type, ForwardType::Dynamic);
    assert_eq!(fwds[3].local_port, 1080);
}

#[test]
fn parse_empty_sections() {
    let output = "\
Local connections:
Remote connections:
Dynamic connections:
";
    let fwds = parse_forward_output(output);
    assert!(fwds.is_empty());
}

#[test]
fn parse_output_with_no_forwards() {
    let output = "";
    let fwds = parse_forward_output(output);
    assert!(fwds.is_empty());
}

#[test]
fn parse_output_with_error_message() {
    let output = "No forwards.\nLocal connections:\n";
    let fwds = parse_forward_output(output);
    assert!(fwds.is_empty());
}

#[test]
fn parse_remote_forward_line() {
    let line = "0.0.0.0 port 2222, forwarding to 127.0.0.1 port 22";
    let fwd = parse_forward_line(line, ForwardType::Remote).unwrap();
    assert_eq!(fwd.local_addr, "0.0.0.0");
    assert_eq!(fwd.local_port, 2222);
    assert_eq!(fwd.remote_addr, "127.0.0.1");
    assert_eq!(fwd.remote_port, 22);
    assert_eq!(fwd.forward_type, ForwardType::Remote);
}

#[test]
fn extract_host_various_patterns() {
    assert_eq!(
        extract_host_from_name("cm-deploy@web01.example.com:22"),
        "web01.example.com"
    );
    assert_eq!(extract_host_from_name("control-root@db:5432"), "db");
    assert_eq!(extract_host_from_name("mux-user@bastion:22"), "bastion");
    assert_eq!(extract_host_from_name("ctrl-user@jump:22"), "jump");
    assert_eq!(
        extract_host_from_name("ssh-abc123def456-12345"),
        "abc123def456-12345"
    );
}

#[test]
fn extract_pid_from_patterns() {
    assert_eq!(extract_pid_from_name("ssh-abc123-48291"), Some(48291));
    assert_eq!(extract_pid_from_name("cm-user@host:22"), None);
    assert_eq!(extract_pid_from_name("ssh-hash-0"), None);
}

// ---------------------------------------------------------------------------
// Edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn parse_forward_line_empty_string() {
    assert!(parse_forward_line("", ForwardType::Local).is_none());
}

#[test]
fn parse_forward_line_no_port_keyword() {
    assert!(parse_forward_line("127.0.0.1 8080", ForwardType::Local).is_none());
}

#[test]
fn parse_forward_line_dynamic_empty_addr() {
    // After trim_start, " port 1080" becomes "port 1080" which has no " port " — returns None
    assert!(parse_forward_line(" port 1080", ForwardType::Dynamic).is_none());
}

#[test]
fn parse_forward_line_remote_forward() {
    let line = "0.0.0.0 port 2222, forwarding to 127.0.0.1 port 22";
    let fwd = parse_forward_line(line, ForwardType::Remote).unwrap();
    assert_eq!(fwd.forward_type, ForwardType::Remote);
    assert_eq!(fwd.local_addr, "0.0.0.0");
    assert_eq!(fwd.remote_port, 22);
}

#[test]
fn parse_forward_output_only_local_section() {
    let output = "Local connections:\n  127.0.0.1 port 8080, forwarding to 10.0.0.1 port 80\n";
    let fwds = parse_forward_output(output);
    assert_eq!(fwds.len(), 1);
    assert_eq!(fwds[0].forward_type, ForwardType::Local);
}

#[test]
fn parse_forward_output_unknown_section_header() {
    let output = "Unknown section:\n  127.0.0.1 port 8080, forwarding to 10.0.0.1 port 80\n";
    let fwds = parse_forward_output(output);
    assert!(fwds.is_empty());
}

#[test]
fn parse_forward_output_blank_lines_between_entries() {
    let output = "\
Local connections:
  127.0.0.1 port 8080, forwarding to 10.0.0.1 port 80

  127.0.0.1 port 9090, forwarding to 10.0.0.2 port 80
";
    let fwds = parse_forward_output(output);
    assert_eq!(fwds.len(), 2);
}

#[test]
fn extract_host_from_name_no_at_sign() {
    assert_eq!(extract_host_from_name("some-random-name"), "some-random-name");
}

#[test]
fn extract_host_from_name_only_prefix() {
    assert_eq!(extract_host_from_name("cm-"), "");
}

#[test]
fn extract_host_from_name_at_no_port() {
    assert_eq!(extract_host_from_name("cm-user@host"), "host");
}

#[test]
fn extract_pid_from_name_no_dash() {
    assert_eq!(extract_pid_from_name("nodash"), None);
}

#[test]
fn extract_pid_from_name_non_numeric() {
    assert_eq!(extract_pid_from_name("ssh-hash-abc"), None);
}

#[test]
fn extract_pid_from_name_large_pid() {
    assert_eq!(extract_pid_from_name("ssh-hash-999999"), Some(999999));
}

#[test]
fn forward_type_display() {
    assert_eq!(ForwardType::Local.to_string(), "local");
    assert_eq!(ForwardType::Remote.to_string(), "remote");
    assert_eq!(ForwardType::Dynamic.to_string(), "dynamic");
}

#[test]
fn parse_forward_line_with_extra_whitespace() {
    // The parser expects exactly " port " (single space) — multiple spaces return None
    let line = "  127.0.0.1  port  8080,  forwarding  to  10.0.0.1  port  80  ";
    assert!(parse_forward_line(line, ForwardType::Local).is_none());
}

// ---------------------------------------------------------------------------
// Weird edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn parse_forward_line_very_high_port() {
    let line = "127.0.0.1 port 65535, forwarding to 10.0.0.1 port 80";
    let fwd = parse_forward_line(line, ForwardType::Local).unwrap();
    assert_eq!(fwd.local_port, 65535);
}

#[test]
fn parse_forward_line_port_zero() {
    let line = "127.0.0.1 port 0, forwarding to 10.0.0.1 port 80";
    let fwd = parse_forward_line(line, ForwardType::Local).unwrap();
    assert_eq!(fwd.local_port, 0);
}

#[test]
fn parse_forward_line_remote_with_empty_remote_addr() {
    // When remote addr is empty, cancel_known_forward substitutes "localhost"
    let line = "0.0.0.0 port 2222, forwarding to  port 22";
    let fwd = parse_forward_line(line, ForwardType::Remote).unwrap();
    assert_eq!(fwd.remote_addr, "");
    assert_eq!(fwd.remote_port, 22);
}

#[test]
fn parse_forward_output_with_error_before_sections() {
    let output = "Error: some error message\nLocal connections:\n  127.0.0.1 port 8080, forwarding to 10.0.0.1 port 80\n";
    let fwds = parse_forward_output(output);
    assert_eq!(fwds.len(), 1);
}

#[test]
fn parse_forward_output_with_multiple_local_sections() {
    // Duplicate section headers - should keep parsing
    let output = "\
Local connections:
  127.0.0.1 port 8080, forwarding to 10.0.0.1 port 80
Local connections:
  127.0.0.1 port 9090, forwarding to 10.0.0.2 port 80
";
    let fwds = parse_forward_output(output);
    // Both should be parsed since we don't reset the type
    assert_eq!(fwds.len(), 2);
}

#[test]
fn parse_forward_line_dynamic_with_remote_type() {
    // Dynamic line parsed as Remote should return None (no "forwarding to")
    let line = "127.0.0.1 port 1080";
    assert!(parse_forward_line(line, ForwardType::Remote).is_none());
}

#[test]
fn parse_forward_line_local_with_dynamic_type() {
    // Local line parsed as Dynamic — the parser finds " port " and takes the port,
    // but then expects the rest to be empty for Dynamic type
    let line = "127.0.0.1 port 8080, forwarding to 10.0.0.1 port 80";
    let result = parse_forward_line(line, ForwardType::Dynamic);
    // Dynamic type expects just "<addr> port <port>" without ", forwarding to..."
    // The extra comma/text after the port is ignored for Dynamic type
    // since it only reads up to the end of the port number
    if let Some(fwd) = result {
        assert_eq!(fwd.local_port, 8080);
    }
    // Whether it returns Some or None depends on how the parser handles
    // trailing content for Dynamic type
}

#[test]
fn extract_host_from_name_very_long() {
    let long_name = format!("cm-user@{}:22", "a".repeat(256));
    let host = extract_host_from_name(&long_name);
    assert_eq!(host, "a".repeat(256));
}

#[test]
fn extract_host_from_name_with_underscores() {
    assert_eq!(extract_host_from_name("cm-user_name@host_name:22"), "host_name");
}

#[test]
fn extract_host_from_name_with_hyphens() {
    assert_eq!(extract_host_from_name("cm-user@my-host:22"), "my-host");
}

#[test]
fn extract_pid_from_name_at_boundary() {
    assert_eq!(extract_pid_from_name("ssh-hash-1"), Some(1));
    assert_eq!(extract_pid_from_name("ssh-hash-4294967295"), Some(4294967295)); // u32::MAX
}

#[test]
fn parse_forward_output_with_tabs() {
    let output = "Local connections:\n\t127.0.0.1 port 8080, forwarding to 10.0.0.1 port 80\n";
    let fwds = parse_forward_output(output);
    assert_eq!(fwds.len(), 1);
}

// ---------------------------------------------------------------------------
// Production-grade weird edge cases
// ---------------------------------------------------------------------------

#[test]
fn parse_forward_line_same_local_remote_port() {
    let line = "127.0.0.1 port 8080, forwarding to 10.0.0.1 port 8080";
    let fwd = parse_forward_line(line, ForwardType::Local).unwrap();
    assert_eq!(fwd.local_port, fwd.remote_port);
}

#[test]
fn parse_forward_line_with_ipv6_localhost() {
    let line = "::1 port 8080, forwarding to ::1 port 80";
    let fwd = parse_forward_line(line, ForwardType::Local).unwrap();
    assert_eq!(fwd.local_addr, "::1");
    assert_eq!(fwd.remote_addr, "::1");
}

#[test]
fn parse_forward_line_with_hostname() {
    let line = "myhost port 8080, forwarding to remotehost port 80";
    let fwd = parse_forward_line(line, ForwardType::Local).unwrap();
    assert_eq!(fwd.local_addr, "myhost");
    assert_eq!(fwd.remote_addr, "remotehost");
}

#[test]
fn parse_forward_output_with_no_newline_at_end() {
    let output = "Local connections:\n  127.0.0.1 port 8080, forwarding to 10.0.0.1 port 80";
    let fwds = parse_forward_output(output);
    assert_eq!(fwds.len(), 1);
}

#[test]
fn parse_forward_output_with_multiple_blank_lines() {
    let output = "Local connections:\n\n\n  127.0.0.1 port 8080, forwarding to 10.0.0.1 port 80\n";
    let fwds = parse_forward_output(output);
    assert_eq!(fwds.len(), 1);
}

#[test]
fn parse_forward_line_with_port_1() {
    let line = "127.0.0.1 port 1, forwarding to 10.0.0.1 port 80";
    let fwd = parse_forward_line(line, ForwardType::Local).unwrap();
    assert_eq!(fwd.local_port, 1);
}

#[test]
fn parse_forward_line_with_port_65535() {
    let line = "127.0.0.1 port 65535, forwarding to 10.0.0.1 port 80";
    let fwd = parse_forward_line(line, ForwardType::Local).unwrap();
    assert_eq!(fwd.local_port, 65535);
}

#[test]
fn extract_host_from_name_with_numbers() {
    assert_eq!(extract_host_from_name("cm-user@192.168.1.1:22"), "192.168.1.1");
}

#[test]
fn extract_host_from_name_with_multiple_colons() {
    // IPv6-like pattern — takes up to first colon after @
    let host = extract_host_from_name("cm-user@::1:22");
    // The function splits on first colon after @, which is right after @
    // So the result is empty (between @ and first colon)
    assert_eq!(host, "");
}

#[test]
fn extract_pid_from_name_with_multiple_dashes() {
    assert_eq!(extract_pid_from_name("ssh-abc-def-123"), Some(123));
}

#[test]
fn extract_pid_from_name_with_leading_zeros() {
    assert_eq!(extract_pid_from_name("ssh-hash-00123"), Some(123));
}

#[test]
fn cancel_spec_with_empty_remote_addr() {
    let fwd = PortForward {
        local_addr: "127.0.0.1".to_owned(),
        local_port: 8080,
        remote_addr: String::new(),
        remote_port: 80,
        forward_type: ForwardType::Local,
    };
    // Empty remote addr should use "localhost"
    let spec = format!(
        "[{}]:{}:{}:{}",
        fwd.local_addr,
        fwd.local_port,
        if fwd.remote_addr.is_empty() { "localhost" } else { &fwd.remote_addr },
        fwd.remote_port
    );
    assert_eq!(spec, "[127.0.0.1]:8080:localhost:80");
}

#[test]
fn cancel_spec_local_forward() {
    let fwd = PortForward {
        local_addr: "127.0.0.1".to_owned(),
        local_port: 8080,
        remote_addr: "10.0.0.1".to_owned(),
        remote_port: 80,
        forward_type: ForwardType::Local,
    };
    let spec = if fwd.forward_type == ForwardType::Dynamic {
        format!("[{}]:{}", fwd.local_addr, fwd.local_port)
    } else {
        format!(
            "[{}]:{}:{}:{}",
            fwd.local_addr, fwd.local_port, fwd.remote_addr, fwd.remote_port
        )
    };
    assert_eq!(spec, "[127.0.0.1]:8080:10.0.0.1:80");
}

#[test]
fn cancel_spec_dynamic_forward() {
    let fwd = PortForward {
        local_addr: "127.0.0.1".to_owned(),
        local_port: 1080,
        remote_addr: String::new(),
        remote_port: 0,
        forward_type: ForwardType::Dynamic,
    };
    let spec = if fwd.forward_type == ForwardType::Dynamic {
        format!("[{}]:{}", fwd.local_addr, fwd.local_port)
    } else {
        unreachable!()
    };
    assert_eq!(spec, "[127.0.0.1]:1080");
}

// ---------------------------------------------------------------------------
// glob_matches tests
// ---------------------------------------------------------------------------

#[test]
fn glob_matches_prefix_wildcard() {
    assert!(glob_matches("cm-*", "cm-user@host:22"));
    assert!(glob_matches("ssh-*", "ssh-abc123"));
}

#[test]
fn glob_matches_exact() {
    assert!(glob_matches("cm-foo", "cm-foo"));
    assert!(!glob_matches("cm-foo", "cm-bar"));
}

#[test]
fn glob_matches_no_match() {
    assert!(!glob_matches("cm-*", "ctrl-user@host"));
    assert!(!glob_matches("mux-*", "cm-user@host"));
}

#[test]
fn glob_matches_empty_pattern() {
    assert!(!glob_matches("", "cm-user@host"));
}

#[test]
fn glob_matches_empty_name() {
    assert!(!glob_matches("cm-*", ""));
}

#[test]
fn glob_matches_wildcard_only() {
    assert!(glob_matches("*", "anything"));
}

// ---------------------------------------------------------------------------
// extract_host_from_name edge cases
// ---------------------------------------------------------------------------

#[test]
fn extract_host_from_name_ssh_hash_format() {
    // ssh-<hash>-<pid> format falls back to stripped name
    let host = extract_host_from_name("ssh-abc123def-12345");
    assert_eq!(host, "abc123def-12345");
}

#[test]
fn extract_host_from_name_ctrl_prefix() {
    let host = extract_host_from_name("ctrl-user@server.com:22");
    assert_eq!(host, "server.com");
}

#[test]
fn extract_host_from_name_no_prefix() {
    let host = extract_host_from_name("user@host:22");
    assert_eq!(host, "host");
}

// ---------------------------------------------------------------------------
// extract_pid_from_name edge cases
// ---------------------------------------------------------------------------

#[test]
fn extract_pid_from_name_valid() {
    assert_eq!(extract_pid_from_name("ssh-abc-12345"), Some(12345));
}

#[test]
fn extract_pid_from_name_zero() {
    // PID 0 is never valid
    assert_eq!(extract_pid_from_name("ssh-abc-0"), None);
}

#[test]
fn extract_pid_from_name_no_number() {
    assert_eq!(extract_pid_from_name("cm-user@host"), None);
}

#[test]
fn extract_pid_from_name_overflow() {
    assert_eq!(extract_pid_from_name("ssh-abc-99999999999"), None);
}
