# Survey: Homebrew JSON API (formulae.brew.sh)

Surveyed 2026-09-28. All JSON in this brief was fetched live from
`https://formulae.brew.sh` during this survey (host verified reachable, `curl
-s -m 10` → HTTP 200). Fixtures live in
`crates/toride-registry/tests/fixtures/homebrew/`, each with a sibling
`*_meta.json` recording the fetch. Nothing was trimmed — all three fixtures are
3.2–4.3 KB, far below the ~120 KB threshold.

## 1. Endpoints a Rust client would call

| Purpose | URL pattern | Shape |
|---|---|---|
| Single cask | `GET https://formulae.brew.sh/api/cask/{token}.json` | JSON object |
| Single formula | `GET https://formulae.brew.sh/api/formula/{name}.json` | JSON object |
| Full cask catalog | `GET https://formulae.brew.sh/api/cask.json` | JSON array of cask objects |
| Full formula catalog | `GET https://formulae.brew.sh/api/formula.json` | JSON array of formula objects |
| Analytics (optional) | `GET https://formulae.brew.sh/api/analytics/{install,install-on-request,build-error}/{30d,90d,365d}.json` | JSON object |

Source: <https://formulae.brew.sh/docs/api/>; per-item endpoints are described
as the `brew info --json` (formula) / `brew info --json=v2 --cask` (cask)
output "with extra keys containing analytics data and generation date". The
docs page states no formal versioning or stability guarantees — parse
defensively (unknown keys, `null` values everywhere).

`Content-Type` observed on catalog endpoints: `application/json; charset=utf-8`.

Practical notes for a client:

- Per-item is cheap (a few KB); the catalogs are the full databases
  (~7,000+ formulae, ~7,000+ casks, tens of MB) — stream-parse if used, and
  prefer per-item lookups for a single package.
- Catalog list items carry the same normalization-relevant fields as per-item
  objects; the per-item file additionally carries `analytics` and
  `generated_date`.
- Token in the URL is the lowercase `token` (e.g. `brave-browser`,
  `visual-studio-code`, `ripgrep`). Cask tokens are hyphenated lowercase;
  formula names too. `old_tokens` / `oldnames` list previous names (renames).

## 2. Catalog list-item shape (probed live, first ~2 KB only)

Probed with `curl -s https://formulae.brew.sh/api/cask.json | head -c 2000`
(and `/api/formula.json` likewise); full catalogs were **not** saved.

- `cask.json` items: a top-level JSON array whose first element is
  `{"token":"0-ad","full_token":"0-ad","old_tokens":[],"tap":"homebrew/cask","name":["0 A.D."],"desc":"Real-time strategy game","homepage":"…","url":"…","url_specs":{},"version":"0.28.0",…,"sha256":"…","artifacts":[{"app":[…],"target":…},{"zap":[…]}],…,"depends_on":{"macos":{}},"auto_updates":null,"deprecated":false,…,"variations":{…}}`
  — i.e. essentially the full per-cask object (including `artifacts` and
  `variations`), minus `analytics`/`generated_date`; `installed` is `null`
  because the API server has nothing installed.
- `formula.json` items: a top-level JSON array; first element
  `{"name":"a2ps","full_name":"a2ps","tap":"homebrew/core","oldnames":[],"aliases":[],"desc":"…","license":"GPL-3.0-or-later","homepage":"…","versions":{"stable":"4.15.8","head":null,"bottle":true},"urls":{"stable":{"url":"…","checksum":"…"}},…,"bottle":{"stable":{"files":{"arm64_golden_gate":{…},…}}},…,"dependencies":[],"build_dependencies":[],…}`
  — again the per-item object sans `analytics`/`generated_date`.

Conclusion: one serde model per package type serves both per-item and catalog
parsing; only `analytics`/`generated_date` are per-item-only (use
`#[serde(default)]`).

## 3. Cask field inventory (normalization-relevant)

Verified live in `cask-brave-browser.json` and `cask-visual-studio-code.json`.
Types are as observed; assume every field can be `null` unless noted.

| Field | Type (observed) | Meaning / normalization use |
|---|---|---|
| `token` | str | Canonical short id, e.g. `"brave-browser"` — use for `brew install --cask <token>` |
| `full_token` | str | Fully-qualified token (equal to `token` for homebrew/cask) |
| `old_tokens` | []str | Renamed-from tokens (redirect aliases) |
| `tap` | str | `"homebrew/cask"` |
| `name` | []str | Display names; cask `name` is an **array** (`["Brave"]`, `["Microsoft Visual Studio Code","VS Code"]`) — take `[0]` for a single display name |
| `desc` | str | One-line description — maps to registry "description" |
| `homepage` | str | Project URL — maps to registry "homepage" |
| `url` | str | Download URL **for the API's default platform** (arm64 macOS here): brave → `…/stable-arm64/196.59/Brave-Browser-arm64.dmg`; vscode → `…/1.139.1/darwin-arm64/stable` |
| `url_specs` | map | Extra URL options (empty in both fixtures) |
| `version` | str | Upstream version string, e.g. `"1.96.59.0"`, `"1.139.1"` — maps to registry "version" |
| `sha256` | str | **SHA-256 of the `url` artifact, published directly in the JSON** (64 hex chars). This is the checksum of the default-platform download |
| `autobump` | bool | Auto-bumped by Homebrew's version bot |
| `no_autobump_message` | str? | Why autobump is off (`null` here) |
| `skip_livecheck` | bool | Livecheck disabled for this cask |
| `installed` / `installed_time` | null | Always `null` server-side (reflects a local brew, not the registry) — ignore |
| `bundle_version` / `bundle_short_version` | str? | CFBundleVersion / CFBundleShortVersionString override, else `null` |
| `pinned` / `pinned_version` / `outdated` | bool/null | Local-state echoes; `null`/`false` from the API — ignore |
| `artifacts` | []obj | Install/uninstall steps, ordered — see §5 |
| `caveats` / `caveats_rosetta` | str? | Post-install notes (`null` here) |
| `depends_on` | obj | e.g. `{"macos":{">=":["13"]}}` (brave) or `{"macos":{}}` (vscode). Keys: `macos`, `arch`, `formula`, `cask`. The `macos` value is a comparison map: `>=`/`<`/`=` over macOS release names |
| `conflicts_with` | obj? | Conflicting casks/formulas (`null` here) |
| `container` | obj? | Archive container hints (null for dmg/pkg) |
| `rename` | [] | Path renames |
| `auto_updates` | bool? | `true` = the app updates itself (Sparkle etc.), so `brew outdated` will not see new versions; `null` = undeclared. Per Cask Cookbook: set when the app has real self-update, not a mere "check for updates" webpage |
| `deprecated` | bool | Cask deprecated (still installable) |
| `deprecation_date` / `deprecation_reason` / `deprecation_replacement_formula` / `deprecation_replacement_cask` / `deprecate_args` | ? | Deprecation metadata (`null` here) |
| `disabled` / `disable_date` / `disable_reason` / `disable_replacement_*` / `disable_args` | ? | Fully disabled cask (cannot install); all `false`/`null` here |
| `tap_git_head` | str | Tap commit the JSON was generated from |
| `languages` | []str | Localized variants |
| `ruby_source_path` | str | e.g. `"Casks/b/brave-browser.rb"` — source of truth in the tap |
| `ruby_source_checksum` | `{sha256}` | SHA-256 of the Ruby source file |
| `variations` | map | Platform overrides — see §4 |
| `supported_platforms` | []str | Expanded list, e.g. `["golden_gate","arm64_golden_gate","tahoe","arm64_tahoe","sequoia","arm64_sequoia","sonoma","arm64_sonoma","ventura","arm64_ventura"]` (vscode adds `monterey`,`arm64_monterey`,`big_sur`,`arm64_big_sur`) |
| `analytics` | obj | `{"install":{"30d":{token:N},"90d":{…},"365d":{…}}}` — popularity signal only |
| `generated_date` | str | JSON generation date (`"2026-09-28"`) |

## 4. `variations`: per-macOS-version / per-arch overrides

`variations` keys are platform tags. Observed keys: brave → `golden_gate`,
`tahoe`, `sequoia`, `sonoma`, `ventura`, `x86_64_linux`, `arm64_linux`;
vscode additionally has `monterey`, `big_sur`, `arm64_big_sur`. Naming scheme:
`{macos_release}` = Intel build for that release, `arm64_{release}` = Apple
silicon build, `{arch}_linux` = Linux builds.

Each variation value is a **partial object whose keys override the top-level
fields**. Observed payloads:

```json
// brave variations["golden_gate"] — different URL + sha256 for Intel macOS 26
{"url":"https://updates-cdn.bravesoftware.com/sparkle/Brave-Browser/stable/196.59/Brave-Browser-x64.dmg",
 "sha256":"fbeca8107c308993d343cd33857f40ab1812d51ee0502ac86872aaf7e7f5bdd8"}
// brave variations["arm64_linux"] — Linux has no binary
{"sha256":null}
// vscode variations["arm64_big_sur"] — may also override version/livecheck
{"url":"…","version":"…","skip_livecheck":false,"sha256":"…"}
```

Normalization rule: start from the top-level `url`/`sha256`/`version` (the
default platform), then shallow-merge the variation matching the host
(macos-release × arch); a `null` value means "not available for this
platform".

## 5. `artifacts`: install / uninstall / zap semantics

`artifacts` is an **ordered list** of single-key objects. Verified live:

- **brave-browser**: `[{app:["Brave Browser.app"], target:"/Applications/Brave Browser.app"}, {zap:[{trash:[…6 paths], rmdir:[…2 dirs]}]}]`
- **visual-studio-code**: `[{uninstall:[{launchctl:"com.microsoft.VSCode.ShipIt", quit:"com.microsoft.VSCode"}]}, {app:["Visual Studio Code.app"], target:"/Applications/Visual Studio Code.app"}, {binary:["$APPDIR/Visual Studio Code.app/Contents/Resources/app/bin/code"], target:"$HOMEBREW_PREFIX/bin/code"}, {binary:[…code-tunnel], target:"$HOMEBREW_PREFIX/bin/code-tunnel"}, {zap:[{trash:[…10 paths]}]}]`

Artifact kinds and meanings (grounded in the Cask Cookbook,
docs.brew.sh/Cask-Cookbook):

- **`app`** — "Relative path to an .app that should be moved into the
  /Applications folder on installation." Payload: `[name]` plus sibling
  `target` (absolute destination; honors `target:` renaming).
- **`pkg`** — "Relative path to a .pkg file containing the distribution."
  (none in these two fixtures). A `pkg` install **requires** a companion
  `uninstall` stanza.
- **`binary`** — "Relative path to a Binary that should be linked into the
  `$(brew --prefix)/bin` folder on installation" (symlink, not copy).
  Placeholders in payload: `$APPDIR` = the installed .app dir,
  `$HOMEBREW_PREFIX` = brew prefix; `target` is the resulting symlink path.
- **`uninstall`** — "Procedures to uninstall a cask — the normal removal
  path". A list of directive maps; directives observed in the wild:
  `launchctl` (unload/remove launchd jobs), `quit` (Apple-Event quit so save
  dialogs appear), `signal` (fallback when quit fails), `delete`,
  `trash` (move to Trash), `rmdir` (remove if empty, recursive),
  `script` (run uninstall script). Optional *unless* a `pkg`/`installer`
  artifact exists. Note vscode places its `uninstall` artifact **first**, and
  brew runs uninstall steps before moving new files in during upgrade.
- **`zap`** — "Additional procedures for a more complete uninstall, including
  user files and shared resources… Only runs when the user passes `--zap`."
  Same directive vocabulary as `uninstall` (here: `trash` of
  `~/Library/...` paths, `rmdir` of emptied parents). Zap must not remove
  user-created documents. It is *not* part of a normal uninstall — map it to
  a separate "purge user data" action, never to plain uninstall.
- Other install kinds that exist but are absent from these fixtures:
  `binary` outside app bundles, `colorpicker`/`font`/`input_method`/
  `internet_plugin`/`keyboard_layout`/`prefpane`/`qlplugin`/`mdimporter`/
  `screen_saver`/`service`/`suite`/`artifact` (generic with `target:`),
  `installer` (manual steps required), `stage_only`, `pkg` variants.

## 6. Mapping cask JSON → client operations

- **Install**: `brew install --cask <token>` using `token` (not `name`).
  Homebrew itself reads `url`/`sha256`/`artifacts` from the tap; a client
  only needs the token. The JSON's `url` + `sha256` let a client verify or
  mirror the download without invoking brew.
- **Uninstall**: `brew uninstall --cask <token>`. This runs the `uninstall`
  artifact directives (launchctl/quit/trash/…). The `zap` artifact is run
  only by `brew uninstall --zap --cask <token>` and additionally removes
  user-level files (preferences, caches) — present for both fixtures
  (brave: 6 `trash` + 2 `rmdir` paths; vscode: 10 `trash` paths). Surface
  zap as an explicit "remove settings/data" option.
- **Version check**: compare `version` in the JSON against the locally
  installed version. Locally, `brew info --json=v2 --cask <token>` or `brew
  list --cask --versions` reports the installed version; the API's
  `installed`/`outdated` fields are always `null`/`false` server-side and
  must not be used. `auto_updates: true` (both fixtures) means the app may
  update itself behind brew's back — a stale local version is not proof the
  app is outdated. `deprecated: true` warns before install.
- **Checksum**: cask JSON publishes the artifact SHA-256 **directly** —
  top-level `sha256` (default platform) and per-variation `sha256` in
  `variations`. No separate checksum file to download. Note the checksum is
  of the *downloaded container* (dmg/pkg/zip), and `url`+`sha256` pairs are
  platform-specific via `variations` (§4).

## 7. Formula (CLI) field inventory — `formula-ripgrep.json`

For completeness, the formula object is what a client needs for CLI tools:

| Field | Observed value (ripgrep) | Use |
|---|---|---|
| `name` / `full_name` | `"ripgrep"` | id for `brew install <name>` |
| `aliases` | `["rg"]` | alt names |
| `desc` / `homepage` / `license` | `"Search tool like grep and The Silver Searcher"` / `https://github.com/BurntSushi/ripgrep` / `"Unlicense"` | normalization |
| `versions` | `{"stable":"15.2.0","head":"HEAD","bottle":true}` | **version = `versions.stable`** |
| `urls.stable` | `{"url":"…/archive/refs/tags/15.2.0.tar.gz","tag":null,"revision":null,"using":null,"checksum":"7605…"}` | source tarball + its sha256 |
| `bottle.stable.files` | keys `arm64_golden_gate`, `arm64_tahoe`, `arm64_sequoia`, `arm64_sonoma`, `sonoma`, `arm64_linux`, `x86_64_linux`; each `{"cellar":":any","url":"https://ghcr.io/v2/homebrew/core/ripgrep/blobs/sha256:…","sha256":"…"}` | prebuilt binary per (arch × macOS release); `root_url` = `"https://ghcr.io/v2/homebrew/core"` |
| `dependencies` / `build_dependencies` | `["pcre2"]` / `["asciidoctor","pkgconf","rust"]` | dependency graph |
| `keg_only` | `false` | not linked into prefix |
| `executables` | `["rg"]` | binaries the formula provides (API extra) |
| `variations` | `{}` (ripgrep needs none) | same override mechanism as casks |
| `deprecated`/`disabled` + metadata | `false`/`false` | same as casks |
| `analytics` | `{"install":{"30d":{…},"90d":{…},"365d":{…}},"install_on_request":{…},"build_error":{…}}` | popularity |
| `service` | `null` | brew services definition, if any |

Unlike casks, a formula's *bottles* (not the source `urls.stable`) are what
`brew install` pours; bottle `sha256` values are published per-platform in
`bottle.stable.files.{platform}.sha256`.

## 8. Fixtures

| File | Bytes | Source |
|---|---|---|
| `tests/fixtures/homebrew/cask-brave-browser.json` | 3237 | live |
| `tests/fixtures/homebrew/cask-visual-studio-code.json` | 4256 | live |
| `tests/fixtures/homebrew/formula-ripgrep.json` | 3951 | live |
| `tests/fixtures/homebrew/*_meta.json` | — | provenance (`{"synthetic": false, "url": …}`) |

All three were fetched unmodified on 2026-09-28 with
`curl -s -m 30 <url> -o <file>`; no analytics trimming was required (each file
is <5 KB). Catalog endpoints were probed shape-only (`| head -c 2000`) and
deliberately **not** saved.
