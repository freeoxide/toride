use super::*;
use crate::paths::UfwPaths;
use crate::spec::*;

// ---------------------------------------------------------------------------
// ensure_app_profile
// ---------------------------------------------------------------------------

#[test]
fn ensure_app_profile_should_create_new_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("etc/ufw/applications.d")).unwrap();
    let paths = UfwPaths::with_root(dir.path());

    let spec = AppProfileSpec {
        name: "MyApp".into(),
        title: "My Application".into(),
        description: "Test app".into(),
        ports: vec![AppPort {
            port: "80".into(),
            protocol: "tcp".into(),
        }],
    };

    let created = ensure_app_profile(&paths, &spec, "ufw-kit", None).unwrap();
    assert!(created);

    let content =
        std::fs::read_to_string(dir.path().join("etc/ufw/applications.d/ufw-kit-MyApp")).unwrap();
    assert!(content.contains("[MyApp]"));
    assert!(content.contains("ports=80/tcp"));
}

#[test]
fn ensure_app_profile_should_skip_if_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("etc/ufw/applications.d")).unwrap();
    let paths = UfwPaths::with_root(dir.path());

    let spec = AppProfileSpec {
        name: "MyApp".into(),
        title: "My Application".into(),
        description: "Test app".into(),
        ports: vec![AppPort {
            port: "80".into(),
            protocol: "tcp".into(),
        }],
    };

    let created1 = ensure_app_profile(&paths, &spec, "ufw-kit", None).unwrap();
    assert!(created1);

    let created2 = ensure_app_profile(&paths, &spec, "ufw-kit", None).unwrap();
    assert!(!created2);
}

#[test]
fn ensure_app_profile_should_update_if_changed() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("etc/ufw/applications.d")).unwrap();
    let paths = UfwPaths::with_root(dir.path());

    let spec1 = AppProfileSpec {
        name: "MyApp".into(),
        title: "My Application".into(),
        description: "Test app".into(),
        ports: vec![AppPort {
            port: "80".into(),
            protocol: "tcp".into(),
        }],
    };

    let spec2 = AppProfileSpec {
        name: "MyApp".into(),
        title: "My Application".into(),
        description: "Test app".into(),
        ports: vec![
            AppPort {
                port: "80".into(),
                protocol: "tcp".into(),
            },
            AppPort {
                port: "443".into(),
                protocol: "tcp".into(),
            },
        ],
    };

    ensure_app_profile(&paths, &spec1, "ufw-kit", None).unwrap();
    let updated = ensure_app_profile(&paths, &spec2, "ufw-kit", None).unwrap();
    assert!(updated);

    let content =
        std::fs::read_to_string(dir.path().join("etc/ufw/applications.d/ufw-kit-MyApp")).unwrap();
    assert!(content.contains("80/tcp|443/tcp"));
}

// ---------------------------------------------------------------------------
// remove_app_profile
// ---------------------------------------------------------------------------

#[test]
fn remove_app_profile_should_remove_managed_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("etc/ufw/applications.d")).unwrap();
    let paths = UfwPaths::with_root(dir.path());

    let spec = AppProfileSpec {
        name: "MyApp".into(),
        title: "My Application".into(),
        description: "Test app".into(),
        ports: vec![AppPort {
            port: "80".into(),
            protocol: "tcp".into(),
        }],
    };

    ensure_app_profile(&paths, &spec, "ufw-kit", None).unwrap();
    let removed = remove_app_profile(&paths, "MyApp", "ufw-kit").unwrap();
    assert!(removed);

    let path = dir.path().join("etc/ufw/applications.d/ufw-kit-MyApp");
    assert!(!path.exists());
}

#[test]
fn remove_app_profile_should_return_false_if_missing() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("etc/ufw/applications.d")).unwrap();
    let paths = UfwPaths::with_root(dir.path());

    let removed = remove_app_profile(&paths, "NonExistent", "ufw-kit").unwrap();
    assert!(!removed);
}

// ---------------------------------------------------------------------------
// parse_profile
// ---------------------------------------------------------------------------

#[test]
fn parse_profile_should_parse_ini_content() {
    let content = "\
# Managed by ufw-kit.

[MyApp]
title=My Application
description=Test app
ports=80/tcp|443/tcp
";

    let spec = parse_profile("MyApp", content).unwrap();
    assert_eq!(spec.name, "MyApp");
    assert_eq!(spec.title, "My Application");
    assert_eq!(spec.description, "Test app");
    assert_eq!(spec.ports.len(), 2);
}

#[test]
fn parse_profile_should_parse_range_ports() {
    let content = "[MyApp]\ntitle=Test\ndescription=Test\nports=8000:9000/tcp\n";
    let spec = parse_profile("MyApp", content).unwrap();
    assert_eq!(spec.ports[0].port, "8000:9000");
    assert_eq!(spec.ports[0].protocol, "tcp");
}

// ---------------------------------------------------------------------------
// render_profile
// ---------------------------------------------------------------------------

#[test]
fn render_profile_should_produce_valid_ini() {
    let spec = AppProfileSpec {
        name: "Test".into(),
        title: "Test".into(),
        description: "Test".into(),
        ports: vec![
            AppPort {
                port: "80".into(),
                protocol: "tcp".into(),
            },
            AppPort {
                port: "443".into(),
                protocol: "tcp".into(),
            },
        ],
    };

    let rendered = render_profile(&spec);
    assert!(rendered.contains("Managed by ufw-kit"));
    assert!(rendered.contains("[Test]"));
    assert!(rendered.contains("ports=80/tcp|443/tcp"));
}

// ---------------------------------------------------------------------------
// Edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn ensure_app_profile_should_validate_empty_name() {
    let dir = tempfile::tempdir().unwrap();
    let paths = UfwPaths::with_root(dir.path());

    let spec = AppProfileSpec {
        name: String::new(),
        title: "Test".into(),
        description: "Test".into(),
        ports: vec![AppPort {
            port: "80".into(),
            protocol: "tcp".into(),
        }],
    };

    let result = ensure_app_profile(&paths, &spec, "ufw-kit", None);
    assert!(result.is_err());
}

#[test]
fn ensure_app_profile_should_validate_empty_ports() {
    let dir = tempfile::tempdir().unwrap();
    let paths = UfwPaths::with_root(dir.path());

    let spec = AppProfileSpec {
        name: "Test".into(),
        title: "Test".into(),
        description: "Test".into(),
        ports: vec![],
    };

    let result = ensure_app_profile(&paths, &spec, "ufw-kit", None);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Weird edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn parse_profile_should_handle_missing_fields() {
    let content = "[MyApp]\n";
    let spec = parse_profile("MyApp", content).unwrap();
    assert!(spec.title.is_empty());
    assert!(spec.description.is_empty());
    assert!(spec.ports.is_empty());
}

#[test]
fn render_profile_should_handle_single_port() {
    let spec = AppProfileSpec {
        name: "SSH".into(),
        title: "SSH".into(),
        description: "SSH".into(),
        ports: vec![AppPort {
            port: "22".into(),
            protocol: "tcp".into(),
        }],
    };

    let rendered = render_profile(&spec);
    assert!(rendered.contains("ports=22/tcp"));
}

// ---------------------------------------------------------------------------
// Backup integration tests
// ---------------------------------------------------------------------------

#[test]
fn ensure_app_profile_should_create_backup_when_requested() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // Create existing app profiles directory with a file
    std::fs::create_dir_all(root.join("etc/ufw/applications.d")).unwrap();
    std::fs::create_dir_all(root.join("etc/default")).unwrap();
    std::fs::write(root.join("etc/default/ufw"), "ENABLED=yes\n").unwrap();
    std::fs::write(
        root.join("etc/ufw/applications.d/ufw-kit-OldApp"),
        "[OldApp]\ntitle=Old\n",
    )
    .unwrap();

    let paths = UfwPaths::with_root(root);
    let backup_dir = root.join("backup");

    let spec = AppProfileSpec {
        name: "NewApp".into(),
        title: "New Application".into(),
        description: "New".into(),
        ports: vec![AppPort {
            port: "80".into(),
            protocol: "tcp".into(),
        }],
    };

    let created = ensure_app_profile(&paths, &spec, "ufw-kit", Some(&backup_dir)).unwrap();
    assert!(created);

    // Verify backup was created
    assert!(backup_dir.join("default-ufw").exists());
    assert!(backup_dir.join("applications.d/ufw-kit-OldApp").exists());
}
