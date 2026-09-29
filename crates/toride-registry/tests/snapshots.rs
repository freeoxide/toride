//! Insta snapshots of the normalized output per §7 fixture (DESIGN.md
//! §9). Each test parses one frozen fixture through the same public parse
//! signatures the inline unit tests exercise and snapshots the result, so
//! cross-cutting drift (field drops, dedup regressions, platform/artifact
//! tuple changes) surfaces as a reviewable snapshot diff. The deduped
//! tuples DESIGN.md §9 pins (brave: 2 platforms / 2 artifacts; vscode:
//! 2 platforms / 4 artifacts — default + collapsed Intel + `big_sur` +
//! `arm64_big_sur`) are visible in the `homebrew__cask_*` snapshots.
//!
//! Fixtures are loaded at runtime via the `env!("CARGO_MANIFEST_DIR")`
//! anchor (conventions.md §7 — never `include_str!`). The
//! `appstream/fedora-43-os-metainfo.xml` fixture is reference-only wave-2
//! material (appstream.rs module docs) with no parser, so it has no
//! snapshot. Snapshot payloads are `serde_json::to_string_pretty` of the
//! public Serialize types (the workspace's `insta` declaration enables
//! `serde`, and plain string snapshots match house style).

use toride_registry::sources::appstream::AppstreamAdapter;
use toride_registry::sources::flathub::{parse_appstream_detail, parse_search_envelope};
use toride_registry::sources::homebrew::{parse_cask_json, parse_formula_json};
use toride_registry::sources::repology::parse_repology_project;
use toride_registry::{Adapter, App};

/// Manifest-dir-anchored fixture read (conventions.md §7), panicking with
/// the path on failure.
fn read_fixture(rel: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read fixture `{}`: {err}", path.display()))
}

/// Snapshot one serializable value under `name`.
fn snap(name: &str, value: &impl serde::Serialize) {
    insta::assert_snapshot!(
        name,
        serde_json::to_string_pretty(value).expect("snapshot value serializes")
    );
}

/// The normalized apps of the Debian sid/main DEP-11 fixture — the async
/// `Adapter::search` run on a minimal current-thread runtime (the inline
/// tests' `block_on_search` shape).
fn appstream_fixture_apps() -> Vec<App> {
    let text = read_fixture("appstream/debian-sid-main-amd64.yml");
    let adapter = AppstreamAdapter::from_text(
        &text,
        toride_registry::sources::appstream::decode_catalog_arch("debian-sid-main-amd64.yml"),
    )
    .expect("fixture parses");
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(adapter.search("Firefox"))
        .expect("search ok")
}

#[test]
fn homebrew_cask_brave_browser_snapshot() {
    let app =
        parse_cask_json(&read_fixture("homebrew/cask-brave-browser.json")).expect("fixture parses");
    snap("homebrew__cask_brave_browser", &app);
}

#[test]
fn homebrew_cask_visual_studio_code_snapshot() {
    let app = parse_cask_json(&read_fixture("homebrew/cask-visual-studio-code.json"))
        .expect("fixture parses");
    snap("homebrew__cask_visual_studio_code", &app);
}

#[test]
fn homebrew_formula_ripgrep_snapshot() {
    let app =
        parse_formula_json(&read_fixture("homebrew/formula-ripgrep.json")).expect("fixture parses");
    snap("homebrew__formula_ripgrep", &app);
}

#[test]
fn flathub_search_brave_browser_snapshot() {
    let apps = parse_search_envelope(&read_fixture("flathub/search-brave-browser.json"))
        .expect("fixture parses");
    snap("flathub__search_brave_browser", &apps);
}

#[test]
fn flathub_search_visual_studio_code_snapshot() {
    let apps = parse_search_envelope(&read_fixture("flathub/search-visual-studio-code.json"))
        .expect("fixture parses");
    // The envelope reports 30 total hits but serves 21 per page.
    assert_eq!(apps.len(), 21, "21 hits per the Meilisearch page size");
    snap("flathub__search_visual_studio_code", &apps);
}

#[test]
fn flathub_appstream_brave_snapshot() {
    let app = parse_appstream_detail(&read_fixture("flathub/appstream-com.brave.Browser.json"))
        .expect("fixture parses");
    snap("flathub__appstream_brave", &app);
}

#[test]
fn flathub_appstream_visual_studio_code_snapshot() {
    let app = parse_appstream_detail(&read_fixture(
        "flathub/appstream-com.visualstudio.code.json",
    ))
    .expect("fixture parses");
    snap("flathub__appstream_visual_studio_code", &app);
}

#[test]
fn appstream_debian_sid_main_snapshot() {
    let apps = appstream_fixture_apps();
    assert!(!apps.is_empty(), "the fixture's firefox components match");
    snap("appstream__debian_sid_main_firefox", &apps);
}

#[test]
fn repology_project_brave_browser_snapshot() {
    let candidates = parse_repology_project(&read_fixture("repology/project-brave-browser.json"))
        .expect("fixture parses");
    assert_eq!(candidates.len(), 5, "one candidate per entry, in order");
    snap("repology__project_brave_browser", &candidates);
}
