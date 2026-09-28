# Survey: AppStream / DEP-11 (freedesktop desktop-app catalogs)

Surveyed 2026-09-28. The Debian sid catalog was fetched live during this
survey (`deb.debian.org` verified reachable, `curl -s -m 10` → HTTP 200; the
gzipped sid/main catalog is 8,708,066 bytes → 26,693,974 bytes raw YAML,
2,627 components). Fedora and Ubuntu publication layouts were also probed
live (details in §3). Upstream spec quotes come from the official AppStream
documentation at freedesktop.org (fetched live). Fixtures live in
`crates/toride-registry/tests/fixtures/appstream/`, provenance recorded in a
sibling `_meta.json` (flathub-style, per-filename).

## 1. What AppStream / DEP-11 is

Two layers, one standard:

- **metainfo** — upstream-authored XML per project, shipped *inside* the app's
  package at `/usr/share/metainfo/<id>.metainfo.xml` (older: `.appdata.xml`).
- **catalog** (a.k.a. collection data) — distro-built aggregation of all
  metainfo + `.desktop`-derived data for one repo, published by the distro for
  software centers. This is the "which GUI apps exist in which repo" database
  and the layer toride cares about.

Two catalog serializations exist; XML is the official one, DEP-11 YAML is
"primarily used by Debian and its derivatives" (all AppStream libraries read
both). Debian, Ubuntu and derivatives publish DEP-11 YAML; the spec advises
every other distro to use XML.

Sources: <https://www.freedesktop.org/software/appstream/docs/chap-CatalogData.html>
(§3.1 Catalog XML) and
<https://www.freedesktop.org/software/appstream/docs/sect-AppStream-YAML.html>
(§3.2 DEP-11 YAML).

## 2. Upstream catalog XML shape (spec)

Root element `<components>` with attributes:

| Attribute | Meaning |
|---|---|
| `version` | required, spec version the file targets (currently `"0.14"`) |
| `origin` | required, repository-id (usually the filename without extension) |
| `media_baseurl` | base URL; all media/screenshot/icon URLs become relative |
| `architecture` | optional, disambiguates multiarch ID conflicts |

Per-app `<component>` — at minimum `<id/>`, `<name/>`, `<summary/>`,
`<pkgname/>` (apps also need `<icon/>`). The `type` attribute distinguishes
kinds (`desktop-application`, `console-application`, `font`, …). Relevant
children, exact tag names:

- `<id/>` — short unique id, usually lowercase
- `<pkgname/>` — **the distro package to install** (repeatable; `<source_pkgname/>` optional)
- `<name/>`, `<summary/>`, `<description/>` — translated as a whole (xml:lang)
- `<project_license/>` — SPDX expression (e.g. `GPL-3.0-or-later`); note
  `metadata_license` is a metainfo-only tag, catalogs carry `project_license`
- `<url type="homepage"/>` — repeatable, typed (homepage/bugtracker/translate/…)
- `<icon/>` — types `stock`, `cached`, `remote`, `local`; `width`/`height`/`scale`
- `<categories/>` → `<category>` children (freedesktop menu spec)
- `<keywords/>` → `<keyword>` (translated as a whole)
- `<provides/>` → typed children: **`<binary>`**, `<mediatype>`, `<library>`, `<font>`
- `<releases/>` → `<release version="…" date="…" timestamp="…">` with optional
  `<description>` and `<size type="download">` / `type="installed"`
- `<launchable type="desktop-id"/>` — the `.desktop` id(s) that launch the app
- `<languages/>` → `<lang percentage="…">`; `<content_rating/>`; `<bundle/>`
  (`package`, `flatpak`, `appimage`, `snap`, …); `<suggests/>`;
  `<compulsory_for_desktop/>`; `<developer/>`
- `priority` / `merge` (`append` | `replace` | `remove-component`) control how
  components from multiple files merge

## 3. How distros publish catalogs (verified live 2026-09-28)

### Debian / Ubuntu / derivatives: DEP-11 YAML per suite × component × arch

```
https://deb.debian.org/debian/dists/<suite>/<component>/dep11/Components-<arch>.yml.gz
https://deb.debian.org/debian/dists/<suite>/<component>/dep11/Components-<arch>.yml.xz   (also published)
https://deb.debian.org/debian/dists/<suite>/<component>/dep11/CID-Index-<arch>.json.gz   (id→summary index)
https://deb.debian.org/debian/dists/<suite>/<component>/dep11/icons-<size>.tar.gz        (48x48, 64x64, 128x128)
```

Measured on sid/main: `Components-amd64.yml.gz` 8,708,066 B (last-modified
2026-09-27T20:10Z, ~18 h before this survey's fetch); icon tarballs
`icons-48x48.tar.gz` 3,480,048 B,
`icons-64x64.tar.gz` 6,862,394 B, `icons-128x128.tar.gz` 10,233,919 B — not
tiny, so they were **not** downloaded during this survey. The catalog's own
header field `Origin: debian-sid-main` confirms the spec's
`<suite>-<component>` origin convention. Same layout verified on Ubuntu
(`https://archive.ubuntu.com/ubuntu/dists/{noble,questing}/main/dep11/Components-amd64.yml.gz`
→ HTTP 200 for both).

### Fedora: no repo catalog on the mirrors (verified)

- `repomd.xml` of `releases/{37,38,39,40,43,44}/Everything/x86_64/os` and
  `updates/43/Everything/x86_64` lists **no `appstream` / `appstream-icons`
  data type** (only primary/filelists/other/group/updateinfo) — checked via
  `curl` of each `repodata/repomd.xml`.
- The `fedora-appstream-metadata` RPM (successor of `appstream-data`) in F43
  release, F43 updates and F44 release is a **~12 KB stub**: its zstd/cpio
  payload contains only `usr/share/metainfo/org.fedoraproject.fedora.metainfo.xml`
  (the OS "operating-system" component) + a license file. Saved as
  `fedora-43-os-metainfo.xml` — a live sample of the metainfo XML flavor, not
  a catalog.
- So Fedora's distro-wide GUI-app catalog is **not URL-addressable** today;
  historically it shipped in the `appstream-data` package to
  `/usr/share/app-info/` (Richard Hughes, "Actually shipping AppStream
  metadata in the repodata", 2014 —
  <https://blogs.gnome.org/hughsie/2014/12/17/actually-shipping-appstream-metadata-in-the-repodata/>;
  the "Fedora still does not ship AppStream metadata as part of the regular
  repository metadata, but in a package instead" situation is also noted in
  appstream-github issue #117). F42 and older are archived (EOL) and no longer
  on the main mirror. Do not build a toride Fedora adapter on DEP-11; Fedora
  needs RPM primary repodata instead.

## 4. DEP-11 YAML shape (spec §3.2, cross-checked against the live catalog)

Multi-document YAML stream: header document first, then one document per
component, documents separated by `---`. Observed header in the live sid
catalog (fixture keeps it verbatim):

```yaml
%YAML 1.2
---
File: DEP-11          # required, always DEP-11
Version: "1.0"        # required, AppStream spec version targeted
Origin: debian-sid-main
MediaBaseUrl: https://appstream.debian.org/media/sid
Time: "2026-09-27T20:10:17Z"
```

(`Architecture` and `Priority` are optional header fields.) Component fields
map 1:1 to the XML tags, with localized fields as dicts carrying a mandatory
`C` key plus locale keys. `Type` ∈ {`generic`, `desktop-application`,
`console-application`, `addon`, `codec`, `inputmethod`, `firmware`}. Dict
mappings worth noting:

- `Provides:` dict with keys `libraries`, **`binaries`**, `fonts`,
  `modaliases`, `mediatypes`, `firmware`, `python3`, `dbus`, `ids` —
  e.g. live fixture: `Provides: {mediatypes: [text/html, …, x-scheme-handler/https]}`
  (firefox-esr) and `Provides: {binaries: [amsynth]}` (amsynth, sid/main)
- `Launchable:` dict keyed by launchable type:
  `Launchable: {desktop-id: [firefox-esr.desktop]}`
- `Icon:` dict keyed by `stock` / `cached` / `remote` / `local`; `remote`
  URLs are relative to `MediaBaseUrl` (or the catalog's icon cache)
- `Releases:` list of `{version, type: stable|development, unix-timestamp,
  description?}` (live: `version: "51.0", type: development` for
  org.gnome.TextEditor)
- Screenshots may carry `source-image` and/or `videos` (mutually exclusive);
  version relations use two-char operators `== != << >> <= >=`
- **Strictness:** "Fields not mentioned in this document are not recognized by
  DEP-11 YAML parsers" — a DEP-11 parser may reject unknown keys, so a toride
  serde model should use `#[serde(default)]` + ignore-unknown semantics rather
  than deny_unknown_fields.

### Field frequency across the live sid/main catalog (2,627 components)

| Field | Count | | Field | Count |
|---|---|---|---|---|
| Type / ID / Name / Summary | 2,627 | | Provides | 1,220 |
| Package | 2,626 | | Screenshots | 1,021 |
| Description | 2,469 | | ContentRating | 947 |
| Icon | 2,287 | | Developer | 942 |
| Categories | 2,234 | | Releases | 854 |
| Launchable | 2,203 | | Languages | 432 |
| Keywords | 1,471 | | ProjectGroup | 431 |
| Url | 1,430 | | ProjectLicense | 1,378 |
| Extends | 202 | | Requires | 169 |
| Branding | 158 | | Recommends | 129 |
| Supports | 90 | | Replaces | 20 |
| CompulsoryForDesktops | 16 | | Suggests | 7 |

(`Url` sub-keys observed: homepage 1,427, bugtracker 1,011, help 459,
translate 362, donation 306, faq 98, contact 76, contribute 74.) Takeaway:
`Provides`, `Releases`, `ProjectLicense` are **optional** — model them as
`Option<…>`; `Package` is near-universal but one component lacked it.

Two ID styles coexist in the same catalog: legacy `.desktop`-suffixed IDs
derived by distro tooling (`firefox.desktop`, 1,327 of the 2,627 IDs end in
`.desktop`) and modern upstream reverse-DNS IDs (`org.gnome.TextEditor`,
which carry upstream metainfo fields like `Releases`, `Branding`,
`ProjectLicense`, `Developer`). Match on both.

## 5. Normalization-relevant fields (→ toride's model)

| DEP-11 field | XML tag | Normalization use |
|---|---|---|
| `ID` | `<id/>` | canonical app id (`firefox.desktop`, `org.gnome.TextEditor`) |
| `Name` / `Summary` (`C` locale) | `<name/>` / `<summary/>` | display name / one-liner |
| `Package` | `<pkgname/>` | **distro package name** → install action |
| `ProjectLicense` | `<project_license/>` | SPDX license |
| `Provides.binaries` | `<provides><binary>` | **binary names on PATH — the join key for tool detection** |
| `Provides.mediatypes` | `<provides><mediatype>` | MIME/scheme handlers (weaker signal) |
| `Launchable.desktop-id` | `<launchable type="desktop-id"/>` | `.desktop` id; matches `Type: desktop-application` IDs |
| `Releases[].version` / `unix-timestamp` | `<release>` | latest published version + date |
| header `Origin` + the URL path | `origin` attr | **which distro repo**: suite + component + arch (e.g. `debian-sid-main`, `noble/main`) |
| `Categories` | `<categories/>` | GUI-app filtering (e.g. `Network`, `Utility`) |

## 6. Tooling for querying catalogs

### appstreamcli (reference implementation, C; Debian package `appstream`)

Metadata pool reads `/usr/share/swcatalog/{xml,yaml,icons}` (new
freedesktop catalog layout) and `/var/(lib|cache)/swcatalog`, plus legacy
`/usr/share/app-info{,/yaml}` and `/var/cache/app-info` (spec §3.2). Key
subcommands (Debian manpage appstreamcli 1.2.0):

- `appstreamcli refresh-cache` — rebuild the pool cache (root; `--force`)
- `appstreamcli search TERM` / `appstreamcli get ID` — query the pool
- `appstreamcli what-provides TYPE TERM` — "Return components which provide a
  given item", e.g. `appstreamcli what-provides mediatype "text/xml"`; the
  manpage documents `mediatype` and `lib` types (the upstream `provides`
  item-type set also includes binary/lib/font/modalias/mimetype — the fixture's
  `Provides: binaries:` ↔ `<provides><binary>` is exactly the item class this
  queries)
- `appstreamcli validate FILES` (+ `--pedantic`), `convert FILE1 FILE2`
  (XML↔YAML), `dump ID`, `os-info`, `make-desktop-file`, `new-template`
- Global: `--no-net`, `--details`, `--version`

### Rust crate ecosystem (checked crates.io 2026-09-28)

| Crate | Version | Assessment |
|---|---|---|
| `appstream` | 0.2.2 (2022-01-16, 15.5k DL) | Pure-Rust **XML-only** parser (xmltree + optional flate2 gzip via `Collection::from_gzipped`, `find_by_id`); no DEP-11 YAML; unmaintained ~4.5 years |
| `libappstream` / `libappstream-sys` | 0.4.0 | FFI bindings to the C libappstream (full format support incl. DEP-11) at the cost of a C toolchain + system lib |
| `appstream-glib(-sys)` | 0.0.1 | abandoned bindings to the older appstream-glib C library |

**Recommendation:** don't pull either. DEP-11 YAML is flat and stable — parse
it directly with `serde_yaml` into a small model (`Type`, `ID`, `Package`,
`Name`/`Summary` maps, `Provides.binaries`, `Launchable`, `Releases`,
`Origin` header), defaulting every field (§4 strictness). This keeps toride's
adapter pure-Rust and dependency-light, and the fixture exercises exactly
those fields.

## 7. What a toride adapter would do (app → distro package name)

1. **Fetch** `dists/<suite>/<component>/dep11/Components-<arch>.yml.gz` for
   the target distro (Debian/Ubuntu layouts are identical; Fedora has none —
   §3), decompress with `flate2`, feed the stream to a multi-doc YAML reader
   (`serde_yaml::Deserializer::from_reader` yields one document per
   component; first document = header → keep `Origin` as the repo identity).
2. **Filter** to `Type: desktop-application` (and optionally
   `console-application` for CLI tools).
3. **Join on binaries**: for each detected tool binary name, match against
   `Provides.binaries` (falling back to `Package` exact-match, then
   `Launchable.desktop-id` / `ID` basename). `Provides: binaries: [amsynth]`
   is the shape; the majority of components lack `binaries` entirely (54% of
   sid/main has no `Provides` block at all — .desktop-derived ones like
   firefox carry only `mediatypes`), so `Package`/ID matching is the
   necessary fallback.
4. **Emit** a normalized entry: app id, C-locale name/summary, license,
   latest release (`Releases[0].version` + `unix-timestamp`), and the
   **install target = `Package`** scoped to the repo from `Origin`/URL
   (`debian sid main` → `apt install <package>`; `ubuntu noble main` → same
   with the right sources).
5. Cache the catalog (8.7 MB gz / ~27 MB raw for sid/main — download and
   stream-split, don't hold it all in memory; `CID-Index-<arch>.json.gz` is a
   lighter id→summary index if full entries aren't needed).

## 8. Fixtures

| File | Bytes | Source |
|---|---|---|
| `tests/fixtures/appstream/debian-sid-main-amd64.yml` | 9,439 | **live** (subset + trimmed, see `_meta.json`) |
| `tests/fixtures/appstream/fedora-43-os-metainfo.xml` | 3,898 | **live** (verbatim from the stub RPM) |
| `tests/fixtures/appstream/_meta.json` | — | per-file provenance (`{"synthetic": false, "url": …}`) |

`debian-sid-main-amd64.yml` keeps the verbatim DEP-11 header plus 3 real
components from the live sid/main catalog: `firefox-esr.desktop` (Package
`firefox-esr`; classic .desktop-derived shape with `Provides.mediatypes`),
`firefox.desktop` (Package `firefox`), and `org.gnome.TextEditor` (Package
`gnome-text-editor`; modern upstream ID with `ProjectLicense`, `Releases`,
`Branding`). Trimming (locale maps to C/en-GB/de/fr, one cached icon,
Screenshots dropped, Languages → 3) is documented in `_meta.json`; no values
were altered.

**Honesty notes:** brave and VS Code are not packaged in Debian sid/main at
all (verified by ID grep over the full catalog), so the ask's "brave or code"
alternative could not come from Debian — `org.gnome.TextEditor` was chosen as
the third representative component instead. No fixture in this survey is
synthetic; both were cut from live-fetched data.
