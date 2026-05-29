use super::*;

#[test]
fn parse_simple_host_block() {
    let input = "\
Host example
    HostName example.com
    User alice
    IdentityFile ~/.ssh/id_ed25519

Host *
    ServerAliveInterval 60
";
    let ast = parse(input);
    assert_eq!(ast.nodes.len(), 3);

    match &ast.nodes[0] {
        ConfigNode::HostBlock { patterns, nodes, .. } => {
            assert_eq!(patterns, &["example"]);
            assert_eq!(nodes.len(), 3);
        }
        _ => panic!("expected HostBlock"),
    }
}

#[test]
fn round_trip_preserves_content() {
    let input = "\
# My SSH config
Host example
    HostName=example.com
    User alice

Host *
    ServerAliveInterval 60
";
    let ast = parse(input);
    let output = ast.to_string_lossless();
    assert_eq!(output, input);
}

#[test]
fn parse_equals_separator() {
    let input = "Host=myserver\n    HostName=192.168.1.1\n";
    let ast = parse(input);
    match &ast.nodes[0] {
        ConfigNode::HostBlock { header, .. } => {
            assert_eq!(header, "Host=myserver");
        }
        _ => panic!("expected HostBlock"),
    }
}

#[test]
fn split_trailing_comment_works() {
    let (val, comment) = split_trailing_comment("hello # a comment");
    assert_eq!(val, "hello");
    assert_eq!(comment, Some("a comment".to_owned()));

    let (val, comment) = split_trailing_comment("no comment");
    assert_eq!(val, "no comment");
    assert_eq!(comment, None);

    let (val, comment) = split_trailing_comment("\"path # here\" # real comment");
    assert_eq!(val, "\"path # here\"");
    assert_eq!(comment, Some("real comment".to_owned()));
}

#[test]
fn parse_directive_with_equals_in_value() {
    let (keyword, sep, rest) = parse_directive_parts("SetEnv FOO=bar");
    assert_eq!(keyword, "SetEnv");
    assert_eq!(sep, Separator::Space);
    assert_eq!(rest, "FOO=bar");
}

#[test]
fn parse_directive_equals_separator() {
    let (keyword, sep, rest) = parse_directive_parts("HostName=example.com");
    assert_eq!(keyword, "HostName");
    assert_eq!(sep, Separator::Equals);
    assert_eq!(rest, "example.com");
}

#[test]
fn round_trip_preserves_tab_indentation() {
    let input = "Host example\n\tHostName example.com\n\tUser alice\n";
    let ast = parse(input);
    let output = ast.to_string_lossless();
    assert_eq!(output, input);
}

#[test]
fn round_trip_with_comment_in_block() {
    let input = "Host example\n    # inline comment\n    HostName example.com\n";
    let ast = parse(input);
    let output = ast.to_string_lossless();
    assert_eq!(output, input);
}
