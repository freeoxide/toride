# Survey: Secondary ecosystems (winget-pkgs, mise registry, AppImage catalog, Nixpkgs)

Surveyed 2026-09-28. Brief-only pass — no adapter implementation. All four
representative samples were **fetched live** during this survey; fixtures live
in `crates/toride-registry/tests/fixtures/ecosystems/`, each directory with a
sibling `_meta.json` recording the exact fetch command and any trimming.
Reachability was probed with `curl -s -m 10`; note that `repology.org`
returned `000` (connection failure) from this sandbox, consistent with the
environment notes — nothing below depends on it, though the Nixpkgs index
carries a `package_repology_repos` field that would cross-reference it.

Bottom line: **all four are later/P2.** None unblocks current work; the
closest to "trivially cheap" is the mise registry because toride already
integrates mise (`crates/toride-mise`), but that same integration makes the
adapter mostly redundant.

---

## 1. winget-pkgs (microsoft/winget-pkgs)

### Reachability
Reachable. `https://raw.githubusercontent.com/…` and `https://api.github.com/`
both answered HTTP 200. Manifest path discovered via the GitHub contents API:

```
GET https://api.github.com/repos/microsoft/winget-pkgs/contents/manifests/b/Brave
→ ["Brave", "BraveOrigin", "BraveUpdater"]           (publishers under b/)
GET …/contents/manifests/b/Brave/Brave
→ ["153.1.95.104", "154.1.96.59", "Beta", "Dev", "Nightly", …]  (version dirs)
```

Path scheme: `manifests/<first-letter-lowercase>/<Publisher>/<PackageId
segments>/<Version>/`. `PackageIdentifier: Brave.Brave` → `b/Brave/Brave/`.

### Shape — one version = a multi-file manifest (observed ManifestVersion 1.12.0)
`154.1.96.59/` contains exactly 4 YAML files (sizes from the API listing):

| File | Bytes | `ManifestType` | Carries |
|---|---|---|---|
| `Brave.Brave.yaml` | 261 | `version` | `PackageIdentifier`, `PackageVersion`, `DefaultLocale: en-US` — the root pointer |
| `Brave.Brave.installer.yaml` | 2822 | `installer` | `InstallerType: exe`, `ProductCode`, `UpgradeBehavior`, `Protocols`, `FileExtensions`, `ReleaseDate`, `ExpectedReturnCodes`, and the `Installers:` list |
| `Brave.Brave.locale.en-US.yaml` | 2876 | `defaultLocale` | `Publisher`, `PublisherUrl`, `Author`, `PackageName`, `License`/`LicenseUrl`, `Copyright`, `ShortDescription`, `Description`, `Tags`, `ReleaseNotes`, `ReleaseNotesUrl`, `Documentations` |
| `Brave.Brave.locale.zh-CN.yaml` | 1104 | `locale` | translations only (not saved) |

The interesting payload is `Installers` — one entry per (Architecture ×
Scope), each with a directly published SHA-256:

```yaml
- Architecture: x64
  Scope: machine
  InstallerUrl: https://github.com/brave/brave-browser/releases/download/v1.96.59/BraveBrowserStandaloneSetup.exe
  InstallerSha256: 825237818B6800270CF3BE49B5C692992F088B6AB7EACD44F46E1745952E615D
  InstallModes: [interactive, silent]
  InstallerSwitches: {Silent: "/silent /install", SilentWithProgress: "/silent /install"}
  ElevationRequirement: elevationRequired
```

Brave 154.1.96.59 ships 6 installers (x86/x64/arm64 × user/machine).
Other observed installer-level keys: `InstallerType`, `InstallerSwitches`
(custom/silent/log), `ExpectedReturnCodes` (mapped to responses like
`alreadyInstalled`, `cancelledByUser`), `UpgradeBehavior`, `ProductCode`.

### What an adapter would parse
- **Identity**: `PackageIdentifier` (`Publisher.Product`) from any of the
  files; `PackageVersion` from root/installer; display name/license/description
  from the `defaultLocale` file (locale file matching root `DefaultLocale`).
- **Version discovery**: list the version directories via the GitHub contents
  API (or git trees API for bulk).
- **Download candidates**: `Installers[]` → (arch, scope, url, sha256).
  Checksums are published directly — no sidecar checksum file — but they are
  Windows binaries (exe/msix/msi/zip), useless on a macOS/Linux host except
  as metadata.

### Coverage value / wave
Largest Windows desktop catalog in existence, but `winget` installs only on
Windows. For toride's current macOS/Linux focus (homebrew + flathub +
appstream fixtures already exist) it is a cross-check/metadata source, or a
future Windows-host feature. **Wave: later/P2.**

---

## 2. mise registry (jdx/mise `registry/`)

### Reachability — the URL in the task brief has moved
`https://raw.githubusercontent.com/jdx/mise-registry/main/registry.toml`
returns **404**, on `master` too, and `GET
https://api.github.com/repos/jdx/mise-registry` → 404 (`jdx/mise` itself is
alive and pushed 2026-09-28). The registry no longer lives in a standalone
repo or a single TOML: it is a **directory of per-tool TOML files** inside
`jdx/mise` — `https://github.com/jdx/mise/tree/main/registry` — one
`<short-name>.toml` per tool (the GitHub contents API listed 1000 entries,
its page cap, so ≥1000 tools).

### Shape (verified on `node.toml`, `ripgrep.toml`, `1password.toml`, `terraform.toml`)
Top-level TOML keys, one file per short tool name:

```toml
aliases = ["rg"]
backends = [
  "aqua:BurntSushi/ripgrep",
  "asdf:https://gitlab.com/wt0f/asdf-ripgrep",
  "cargo:ripgrep",
]
bins = ["rg"]
description = "ripgrep recursively searches directories for a regex pattern…"
test = { cmd = "rg --version", expected = "ripgrep {{version}}" }
version_order = "semver"
```

- `backends` — array of `<backend>:<id>` strings. Observed prefixes:
  `core:` (mise built-ins, e.g. `core:node`), `aqua:`, `asdf:`, `vfox:`,
  `cargo:` (the mapping is ordered — first entry is the preferred backend).
- `bins` — binaries the tool provides (also maps binary → tool name, useful
  for detection).
- `version_order` — `semver` or `source` (affects sorting).
- `test` — `cmd` + `expected` with a `{{version}}` placeholder (an installed-
  version probe template).
- Optional: `detect` files (e.g. node.toml has `detect = ["package.json", …]`)
  and `idiomatic_files` (e.g. `.terraform-version`).

### What an adapter would parse
short name (the filename) → `backends[]` (tool→backend mapping),
`description`, `aliases`, `bins`. This is exactly the shape toride already
consumes at runtime: `mise registry --json` output is deserialized into
`RegistryTool { short, backends, description, aliases, … }` in
`crates/toride-mise/src/tool/registry.rs` — the TOML files are the upstream
of that data.

### Coverage value / wave
Thousands of CLI tools, and toride already ships mise integration — but that
cuts both ways: when mise is installed, `mise registry --json` already
answers the same question locally, so a direct fetch of `registry/<name>.toml`
only adds value for hosts **without** mise (offline name→backend lookup). The
parse itself is trivial (341 B TOML, one HTTP GET, no API/auth/rate-budget
beyond raw.githubusercontent). **Wave: P2 — the cheapest of the four, and the
only one with a pre-existing integration point; do it first if any of these
get done.**

---

## 3. AppImage catalog (appimage.github.io)

### Reachability
Reachable. `https://appimage.github.io/` → 200. The JSON index is
`https://appimage.github.io/feed.json` (200; found by probing — the front
page HTML does not link it directly).

### Shape — JSON Feed v1, metadata-only
Full index: 967,428 bytes, **1611 items**. Top level: `version: 1`,
`home_page_url`, `feed_url`, `description`, `icon`, `favicon`, `expired`,
`items[]`. Item keys observed across the feed: `name`, `description`,
`categories[]`, `authors[{name,url}]`, `license` (SPDX string, sometimes
`LicenseRef-proprietary=<url>`), `links[]`, `icons` (paths like
`Firefox/icons/128x128/default128.png`, or `null`), `screenshots`, `libc`,
`self_contained`, `glibc_required`. `links[]` is the only pointer upstream:

```json
"links": [
  {"type": "GitHub",   "url": "srevinsaju/Firefox-Appimage"},
  {"type": "Download", "url": "https://github.com/srevinsaju/Firefox-Appimage/releases"}
]
```

(Firefox entry; Joplin uses `type: "Install"` against `laurent22/joplin`.)

**Not in the index:** direct AppImage asset URLs, versions, or checksums.
Resolution requires a second hop (GitHub releases API against the
`GitHub`/`Download` link), and no hashes are published anywhere in the
catalog. The source repo (AppImage/appimage.github.io) confirms this:
`data/<name>` is a plain-text upstream repo URL, and `database/<name>/`
holds icons, a screenshot and `.desktop` files that are i18n desktop entries
only (verified against `database/Firefox/firefox-nightly.desktop`) — no
download data.

### What an adapter would parse
Display name, description, categories, license, authors, upstream GitHub
repo (from `links[GitHub]`), glibc floor (`glibc_required`) — i.e. a
name→upstream-repo hint table, not an install source.

### Coverage value / wave
~1.6k entries, desktop-app-oriented (and the browser fixtures used elsewhere
in this workspace confirm the gap: no Brave, no VSCodium; Firefox is there
via a third-party packager). Marginal for CLI tool management; redundant with
Flathub for GUI apps. **Wave: later.**

---

## 4. Nixpkgs (search.nixos.org backend)

### Reachability and how the frontend queries packages
`https://search.nixos.org/` → 200, but `GET /backend` → **401**: the backend
is an Elasticsearch/OpenSearch index behind Basic auth, and the credentials
are embedded **in the public frontend bundle**
`https://search.nixos.org/static/js/index.771b9a4a.js`:

```js
elasticsearchUrl:"/backend",
elasticsearchUsername:"aWVSALXpZv",
elasticsearchPassword:"X8gPHnzL52wFEekuxsfQ9cSh",
searchMappingSchemaVersion:parseInt("51"),
nixosChannels:JSON.parse('{"channels":[
  {"branch":"nixos-26.05","id":"26.05","jobset":"nixos/release-26.05","status":"stable"},
  {"branch":"nixos-unstable","id":"unstable","jobset":"nixos/unstable","status":"rolling"}],
 "default":"26.05"}')
```

Query (verified live, HTTP 200):

```
POST https://search.nixos.org/backend/latest-51-nixos-26.05/_search?request_cache=true
Authorization: Basic <base64("aWVSALXpZv:X8gPHnzL52wFEekuxsfQ9cSh")>
Content-Type: application/json

{"query":{"bool":{"must":[{"term":{"type":"package"}},
                           {"term":{"package_attr_name":{"value":"hello"}}}]}},
 "size":1}
```

Index naming: `latest-<schemaVersion>-<branch>` → `latest-51-nixos-26.05`
and `latest-51-nixos-unstable` both answered 200; the wrong shapes
(`latest-51-unstable`, `latest-51-26.05`) → 404. The schema version (51) and
channel list must be scraped from the JS bundle — they change over time, so
an adapter needs a discovery step before the first query.

### Shape — one `_source` document per package (fixture: `hello` on 26.05)
Keys (all `package_`-prefixed except `type: "package"`): `package_attr_name`
(`hello`), `package_attr_set`, `package_pname`, `package_pversion` (2.12.3),
`package_description`, `package_longDescription` (pre-rendered HTML),
`package_homepage[]`, `package_license[]` (with `spdxId`) + `package_license_set`
+ `package_license_expression`, `package_maintainers[{name,github,email}]`,
`package_programs` (binaries provided — `["hello"]`; strong signal for
tool detection), `package_mainProgram`, `package_outputs` +
`package_default_output`, `package_platforms` (80-entry system list for hello),
`package_dep_count`, `package_hydra`, `package_repology_repos`,
`package_position` (`pkgs/by-name/he/hello/package.nix:57`),
`package_teams`. **No download URL and no hash** — nixpkgs builds from
source via evaluation; the index is search metadata only, so a client would
shell out to `nix profile install nixpkgs#<attr>` rather than fetch artifacts.

### macOS/Linux coverage
Both. `package_platforms` for `hello` includes `x86_64-linux`,
`aarch64-linux`, **`x86_64-darwin`, `aarch64-darwin`** (plus freebsd/windows/
wasm and ~70 more). Nix is a first-class macOS package manager, so this is
the only source surveyed here whose catalog natively spans toride's two
target OSes with one query syntax. Platform-aware filtering is possible:
match the host system against `package_platforms`.

### Coverage value / wave
Entire nixpkgs (tens of thousands of packages, far larger than the other
sources here) queryable per-channel with exact versions. Fragility: the
shared Basic credentials and the schema-versioned index name are informal
contract — they can rotate or break without notice (it's the search site's
private backend, not a published API). **Wave: later/P2** — high coverage,
but the endpoint is unofficial and the install path still needs a local nix.

---

## Fixtures

| File | Bytes | Source URL | Status |
|---|---|---|---|
| `tests/fixtures/ecosystems/winget/Brave.Brave.installer.yaml` | 2822 | raw.githubusercontent.com/microsoft/winget-pkgs/master/manifests/b/Brave/Brave/154.1.96.59/… | live |
| `tests/fixtures/ecosystems/winget/Brave.Brave.locale.en-US.yaml` | 2876 | same dir | live |
| `tests/fixtures/ecosystems/winget/Brave.Brave.yaml` | 261 | same dir | live |
| `tests/fixtures/ecosystems/mise/ripgrep.toml` | 341 | raw.githubusercontent.com/jdx/mise/main/registry/ripgrep.toml | live |
| `tests/fixtures/ecosystems/appimage/feed-trimmed.json` | 2153 | appimage.github.io/feed.json | live, trimmed: 3 of 1611 items (4KWALL first-item, Firefox, Joplin), top-level keys verbatim |
| `tests/fixtures/ecosystems/nixpkgs/search-hello-26.05.json` | 2247 | search.nixos.org/backend/latest-51-nixos-26.05/_search (POST) | live, trimmed: `package_platforms` 80 → 12 entries; rest verbatim |

Each directory also has a `_meta.json` with `{"synthetic": false, "url": …}`
plus the exact fetch command and trimming notes. Probed but deliberately not
saved: the winget zh-CN locale yaml (1104 B), the AppImage per-app
`data/<name>`/`database/<name>/` files, and `latest-51-nixos-unstable`
responses.
