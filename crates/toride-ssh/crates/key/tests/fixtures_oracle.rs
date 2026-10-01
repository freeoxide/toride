use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey};

fn fixture(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read fixture {name}: {e}"))
}

#[test]
fn ed25519_fixture_parses_as_unencrypted_ed25519() {
    let pk = PrivateKey::from_openssh(fixture("id_ed25519")).expect("ed25519 fixture must parse");
    assert_eq!(pk.algorithm(), Algorithm::Ed25519);
    assert!(!pk.is_encrypted(), "bench fixture must be unencrypted");
    assert_eq!(pk.comment().to_string(), "toride-bench-ed25519");
}

#[test]
fn rsa_fixture_parses_as_unencrypted_2048_bit_rsa() {
    let pk = PrivateKey::from_openssh(fixture("id_rsa_2048")).expect("rsa fixture must parse");
    assert!(
        matches!(pk.algorithm(), Algorithm::Rsa { .. }),
        "expected RSA, got {:?}",
        pk.algorithm()
    );
    assert!(!pk.is_encrypted(), "bench fixture must be unencrypted");
    let bits = pk
        .public_key()
        .key_data()
        .rsa()
        .map(ssh_key::public::RsaPublicKey::key_size)
        .unwrap_or_default();
    assert_eq!(bits, 2048, "expected a 2048-bit RSA bench fixture");
}

#[test]
fn private_and_public_fixture_fingerprints_match() {
    for (private_name, public_name) in [
        ("id_ed25519", "id_ed25519.pub"),
        ("id_rsa_2048", "id_rsa_2048.pub"),
    ] {
        let private = PrivateKey::from_openssh(fixture(private_name))
            .unwrap_or_else(|e| panic!("{private_name} must parse: {e}"));
        let public = PublicKey::from_openssh(&fixture(public_name))
            .unwrap_or_else(|e| panic!("{public_name} must parse: {e}"));

        let from_private = private.public_key().fingerprint(HashAlg::Sha256);
        let from_public = public.fingerprint(HashAlg::Sha256);
        assert_eq!(
            from_private.as_bytes(),
            from_public.as_bytes(),
            "{private_name} and {public_name} disagree on the SHA-256 fingerprint"
        );
    }
}

#[test]
fn ed25519_and_rsa_fixtures_are_distinct_keys() {
    let ed = PrivateKey::from_openssh(fixture("id_ed25519")).expect("ed25519 fixture must parse");
    let rsa = PrivateKey::from_openssh(fixture("id_rsa_2048")).expect("rsa fixture must parse");
    assert_ne!(
        ed.public_key().fingerprint(HashAlg::Sha256).as_bytes(),
        rsa.public_key().fingerprint(HashAlg::Sha256).as_bytes()
    );
}
