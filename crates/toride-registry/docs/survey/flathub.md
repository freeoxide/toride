# Flathub API survey

Date: 2026-09-28. All endpoints below were fetched live from this sandbox (HTTP 200 unless
stated otherwise); fixtures live in `crates/toride-registry/tests/fixtures/flathub/`
(provenance in that directory's `_meta.json`, `synthetic: false` throughout).

Flathub is the Linux GUI-app catalog (Flatpak). Its web API is **discovery + metadata only** —
actual installation goes through the `flatpak` CLI against the Flathub OSTree remote (see
[Installing](#installing-what-the-api-does-not-do)).

## API surface (verified live)

The backend ([flathub-infra/website](https://github.com/flathub-infra/website), FastAPI) publishes a
complete OpenAPI 3.1 spec:

- `GET https://flathub.org/api/v2/openapi.json` → fixture `openapi-v2.json` (432 KB, ~200 routes).
  This is the authoritative surface; generated API clients come from it.
- Search: `POST https://flathub.org/api/v2/search` — body `{"query": "brave browser"}`.
- App detail: `GET https://flathub.org/api/v2/appstream/{app_id}` (optional `?locale=`).

Negative results, also verified live:

- `GET /api/v2/app/com.brave.Browser` → **404** `{"detail":"Not Found"}`. There is no `/app/{id}` REST route in v2.
- `GET /api/v1/apps/com.brave.Browser` → **404** (HTML error page). The old v1 API is gone.
- There is no GraphQL endpoint at `/api/v2/graphql` (404, verified).
- Public read routes of note besides the two above: `GET /api/v2/appstream` (list all ids),
  `GET /api/v2/collection/{category|popular|trending|recently-updated|verified|...}`,
  `GET /api/v2/addon/{app_id}` (e.g. codecs), `GET /api/v2/app-picks/...`. All write/admin
  routes require auth and are irrelevant for a read-only registry client.

## Search — `POST /api/v2/search`

Request (`SearchQuery` in the OpenAPI spec; `query` is the only required key):
`{"query": "...", "filters": [...], "hits_per_page": 21, "page": 1}` — defaults `hits_per_page=21`, `page=1`.

Response is a Meilisearch envelope (Flathub's search index is Meilisearch):

```json
{"hits": [...], "query": "...", "processingTimeMs": 887,
 "hitsPerPage": 21, "page": 1, "totalPages": 1, "totalHits": 13,
 "facetDistribution": {...}, "facetStats": {}}
```

Fixtures: `search-brave-browser.json` (13 hits), `search-visual-studio-code.json` (21 hits).

### Fields per hit (`AppsIndex` schema)

| Field | Type (observed) | Example (brave hit) |
|---|---|---|
| `app_id` | string, **required** | `"com.brave.Browser"` |
| `id` | string, required | `"com_brave_Browser"` — `app_id` with dots→underscores (Meilisearch PK quirk) |
| `name` | string, required | `"Brave"` |
| `summary` | string, required | `"Fast Internet, AI, Adblock"` |
| `description` | string (markdown-ish), required | full long description |
| `type` | string, required | `"desktop-application"` |
| `project_license` | string, required | `"MPL-2.0"` / `LicenseRef-proprietary=...` |
| `is_free_license` | bool, required | `true` |
| `icon` | string URL (nullable), required | `https://dl.flathub.org/media/.../com.brave.Browser.png` |
| `main_categories` | **string or array** (anyOf in spec), required | `"network"` |
| `developer_name` | string, required | `"Brave Software"` |
| `verification_verified` | bool, required | `true` |
| `verification_method` | string, required | `"website"` / `"none"` |
| `verification_website` | string, required | `"brave.com"` |
| `verification_timestamp` | string, required | `"1711639797"` |
| `verification_login_{name,provider,is_organization}` | string/string/bool, required | null/null/false |
| `runtime` | string (nullable), required | `"org.freedesktop.Platform/x86_64/25.08"` |
| `arches` | string[] (nullable), required | `["aarch64","x86_64"]` |
| `updated_at` | int (unix secs), required | `1790275315` |
| `added_at` | int (unix secs), optional | `1602485316` |
| `trending` | number (nullable), optional | `-1.99…` |
| `installs_last_month` | int (nullable), optional | `172129` |
| `favorites_count` | int (nullable), optional | `426` |
| `keywords`, `localized_keywords`, `sub_categories`, `translations` | optional | `["vscode"]`, `["WebBrowser"]`, `{}` |

`main_categories` is `anyOf[string, string[]]` in the schema but a bare string in both live
samples — deserialize defensively.

## App detail — `GET /api/v2/appstream/{app_id}`

Full AppStream metadata. The response `type` discriminates `oneOf` Desktop / Addon /
Localization / Generic / Runtime schemas; both sampled apps are `desktop-application`
(`DesktopAppstream`). Fixtures: `appstream-com.brave.Browser.json`,
`appstream-com.visualstudio.code.json`. Top-level fields observed (brave):

| Field | Observed value / shape |
|---|---|
| `id` | `"com.brave.Browser"` (dotted app_id, unlike search's `id`) |
| `name`, `summary` | `"Brave"` / `"Fast Internet, AI, Adblock"` |
| `description` | **HTML** (`<p>…`), unlike search's plain/markdown text |
| `type` | `"desktop-application"` |
| `developer_name` | `"Brave Software"` |
| `project_license`, `is_free_license` | `"MPL-2.0"`, `true` |
| `categories` | `["Network","WebBrowser"]` |
| `releases[]` | `{version, type: "stable", timestamp: "1790208000", date, date_eol, description, urgency, url}` — most recent first; **`releases[0].version` is the current release** (brave `1.96.59`, vscode `1.138.0`); exactly 4 recent releases returned in both samples |
| `bundle` | `{type: "flatpak", value: "app/com.brave.Browser/x86_64/stable", runtime: "org.freedesktop.Platform/x86_64/25.08", sdk: "org.freedesktop.Sdk/x86_64/25.08"}` |
| `urls` | `{homepage, help, faq, contact, donation, translate, vcs_browser, bugtracker, contribute}` (many null) |
| `icons[]` | `{type: "remote", url, width: 128, height: 128, scale}` |
| `screenshots[]` | `{caption, default: bool, sizes[]: {width, height, scale, src}}` |
| `provides[]` | 16 strings (binary/MIME/etc. provided ids) |
| `launchable` | `{type: "desktop-id", value: "com.brave.Browser.desktop"}` |
| `branding[]` | `{type: "primary", scheme_preference: "light", value: "#bd7277"}` |
| `content_rating_details` | per-locale `{contentRatingSystem: "ESRB", minimumAge: 3, minimumAgeText, categories[]: {id, level, description}}` |
| `metadata` | map with `flathub::verification::{verified,method,website,timestamp,login_*}` keys, `flathub::manifest` (null here) |
| `keywords`, `mimetypes`, `kudos`, `translation`, `is_eol`, `isMobileFriendly` | present; usually null/empty/false |

## `app_id` convention

Reverse-DNS, case-sensitive: `com.brave.Browser`, `com.visualstudio.code`. It is the join key
everywhere: search `hits[].app_id`, the `appstream/{app_id}` path, `bundle.value`
(`app/{app_id}/{arch}/stable`), media URLs under `dl.flathub.org/media/{dotted→slash path}/`,
`.flatpakref` `Name=`, and the `flatpak install/run` CLI argument. Watch the search-hit `id`
(`com_brave_Browser`, underscores) — it is the Meilisearch document key, not the app id.

## Installing (what the API does *not* do)

The API never serves the application payload. Installation requires the `flatpak` CLI plus the
Flathub remote, configured once from the signed repo descriptor (fixture `flathub.flatpakrepo`,
live-fetched: `Url=https://dl.flathub.org/repo/` + Flathub GPG key):

```sh
flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
flatpak install flathub com.brave.Browser   # or: --interactive
flatpak run com.brave.Browser
flatpak update
```

(The `remote-add` line is quoted verbatim from flathub.org's setup page, `flathub.org/setup/Debian`.)
`https://dl.flathub.org/repo/appstream/{app_id}.flatpakref` (fixture
`com.brave.Browser.flatpakref`, HTTP 200) is the per-app pointer file desktop software centers
consume; it carries the same repo URL + GPG key + `RuntimeRepo=https://dl.flathub.org/repo/flathub.flatpakrepo`.
Transfers are OSTree static deltas from `dl.flathub.org`, integrity via GPG — not via any API-supplied checksum.

A tool that only wants discovery/metadata can use this HTTP API; a tool that installs must
shell out to `flatpak` (or link libflatpak).

## Limitations (relevant to a registry client)

- **No sha256 / download checksums anywhere in the API.** Verified: no digest/hash field in the
  search hits, the appstream detail, the `.flatpakref`, or the OpenAPI spec. Integrity is
  GPG-signature-based at the OSTree layer; per-object checksums live inside the OSTree repo and
  are not exposed. If toride needs pinned checksums, Flathub cannot provide them via this API.
- **No direct payload download URL.** Only icons/screenshots/media are plain HTTPS on
  `dl.flathub.org`; the app itself is only reachable through the flatpak client/remote.
- **Version availability is opaque.** There is a single `stable` branch per arch
  (`bundle.value`); `releases[]` lists only recent releases (4 observed) and there is no endpoint
  to enumerate or select older versions. "What version would I get?" = `releases[0].version`,
  but only at query time — it changes without notice.
- **Search envelope leaks Meilisearch internals** (`processingTimeMs`, `facetDistribution`,
  `facetStats`) — treat as unstable; the stable contract is the OpenAPI spec itself.
- **`main_categories` anyOf string/array**, `runtime`/`arches`/`icon` nullable despite being
  "required" (required = key present, not non-null) — deserialize permissively.
- **Search `id` vs `app_id`** (underscores vs dots) is an easy conflation bug.
- **No documented rate limit** in the live OpenAPI spec; nothing verified either way.
- `docs.flathub.org/docs/for-users/installation/` 404'd when fetched; user-facing setup docs
  live at `flathub.org/setup/{distro}`. Developer API reference: the `openapi.json` fixture.
