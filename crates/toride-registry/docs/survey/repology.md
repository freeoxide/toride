# Survey: Repology API (repology.org)

Surveyed 2026-09-28. **Repology was NOT reachable from this sandbox.** Verified
with `curl -s -m 10 -o /dev/null -w "%{http_code}" https://repology.org/api/v1/project/brave-browser`
→ `HTTP 000`, curl exit 7 ("Connection refused"); `getent hosts repology.org`
→ `127.0.0.1` — the sandbox pins repology.org's DNS to localhost, so no live
payload could be fetched by any in-sandbox channel. Everything below was
therefore reconstructed from **documented/primary sources on reachable hosts**:
the `repology.org/api` docs page text (captured twice, consistently, via the
harness's server-side web reader, which is not affected by the sandbox DNS
pinning) and the `repology/repology-webapp` + `repology/repology-updater`
source on `raw.githubusercontent.com` / `api.github.com` (both verified
reachable, `curl` → HTTP 200/301).

The sample payload for `brave-browser` is **synthetic** and lives at
`crates/toride-registry/tests/fixtures/repology/project-brave-browser.json`
with a `_meta.json` sibling recording why (`{"synthetic": true, ...}`). Field
*names* below are verified against upstream docs and code; field *values* in
the fixture are invented.

## 1. Endpoint set

Verbatim from the docs template (`repologyapp/templates/api.html`) and the
Flask route registrations (`repologyapp/views/api.py`).

| Purpose | URL pattern | Response shape |
|---|---|---|
| **Single project** (the one to use) | `GET /api/v1/project/<name>` | bare JSON **array** of package entries (`api.py:107-117`) |
| Multiple projects (paged) | `GET /api/v1/projects/` and `/api/v1/projects/<bound>/` | JSON **object**: project name → array of entries (`api.py:79-104`) |
| Repository problems | `GET /api/v1/repository/<repo>/problems` | array of problem objects (`api.py:120-125`) |
| Maintainer problems for a repo | `GET /api/v1/maintainer/<maintainer>/problems-for-repo/<repo>` | array of problem objects (`api.py:128-133`) |
| Distro name map (experimental) | `GET /api/experimental/distromap?fromrepo=<r>&torepo=<r>[&expand=1][&format=plaintext]` | repo-to-repo package-name mapping (`api.py:136-160`) |
| Latest updates (experimental) | `GET /api/experimental/updates` | update log entries (`api.py:163-173`) |
| Alias oracle (redirect, not JSON) | `GET /tools/project-by?repo=&name_type=&name=&target_page=&noautoresolve=` | 302 redirect / 300 JSON / 404 (`views/tools.py:77-139`) |

Legacy naming: the 2017-era API exposed `GET /api/v1/metapackage/<name>` and
`/api/v1/metapackages/...` (see `views/api.py` at commit `74bab7f2`, routes at
lines 58-148); commit `3b999fb1` (2019-02-21, "Rename metapackages->projects in
API endpoints") renamed them to the `/project(s)/` forms above. Current master
has **no** JSON `/api/v1/metapackage` route — only HTML `/metapackage/<name>`
301-redirects to the project pages (`views/legacy.py:30-32`). A client should
speak only `/api/v1/project/...`.

**Repository listing: there is no JSON endpoint for it.** Verified against the
full route set in `views/api.py` — the only `/api/v1/repository/...` route is
`/<repo>/problems`. Repo identifiers and metadata (family, descriptions) are
served as HTML pages (`/repositories/statistics`, `views/repositories.py:28-102`)
and, machine-readable, as per-repo YAML in the `repology-updater` repo
(`repos.d/**.yaml`). Repo IDs used in the API are defined there:
`- name: homebrew` (`repos.d/macosx/homebrew/homebrew.yaml`),
`- name: arch` (`repos.d/arch/arch.yaml`), templated
`name: debian_{{version}}` with `{{ debian(13, 'trixie', ...) }}` →
`debian_13` (`repos.d/deb/debian.yaml:9,171`), `fedora('rawhide', ...)`
→ `fedora_rawhide` (`repos.d/rpm/fedora.yaml`), `alpine('edge', ...)` →
`alpine_edge` (`repos.d/alpine/alpine.yaml`). All five fixture repo IDs are
thus real Repology repo identifiers.

`/api/v1/projects/` filter parameters (docs template, "Filtered projects";
all map to website filters): `search`, `maintainer`, `category`, `inrepo`,
`notinrepo`, `repos` (count/range), **`families`** (count/range of repository
families, e.g. `families=1` → unique projects), `repos_newest`,
`families_newest`, `newest`, `outdated`, `problematic`. The listing returns at
most `METAPACKAGES_PER_PAGE` projects per request (`api.py:88`); iterate by
passing the last project name as the `<bound>` (docs give the
`010editor…aaut…acf-snort` example).

## 2. Per-entry field inventory (`/api/v1/project/<name>`)

Documented example from the API page (verbatim, FreeBSD firefox):

```json
{
    "repo": "freebsd",
    "srcname": "www/firefox",
    "binname": "firefox",
    "visiblename": "www/firefox",
    "version": "50.1.0",
    "origversion": "50.1.0_4,1",
    "status": "newest",
    "summary": "Widely used web browser",
    "categories": ["www"],
    "licenses": ["GPLv2+"],
    "maintainers": ["gecko@FreeBSD.org"]
}
```

Documented semantics: `subrepo` = subrepository (`main`/`contrib`/`non-free`
for Debian); `srcname`/`binname` = source and/or binary package name
(**all name fields optional**); `visiblename` = name as shown on the site;
`version` = sanitized version; `origversion` = version as in the repo;
`summary` = one-line description; `categories`/`licenses`/`maintainers` =
lists. **Mandatory fields are `repo` and `version`; all others are optional.**

Serialization is a fixed allow-list in `api_v1_package_to_json`
(`repologyapp/views/api.py:31-63`, master): `repo`, `subrepo`, `srcname`,
`binname`, `visiblename`, `version`, `maintainers`, `licenses` (each only if
truthy), then unconditionally `status` and `origversion` (set to `null` when
equal to `version`), plus conditionally `summary` (from the DB `comment`
column), `categories` (single category wrapped in a list), and `vulnerable:
true` when the package carries the VULNERABLE flag (`api.py:53-61`).

Era drift (relevant because third-party examples mix eras) — from the
`api.py` commit history:

- ≤2023-03: also serialized **`name`** (removed by `7efb88cb`, 2023-03-29,
  "Remove uses of `name` package field"); ≤2020-01 also `keyname`
  (`10868329`, "Drop deprecated keyname support"); ≤2021-02 also
  `homepage`→`www` and `downloads` (removed by `90011eef`).
- The assignment's expected per-entry set — `repo, srcname, name, version,
  status, families` — matches the 2019-2023 payloads (`name` verified in the
  serializer at commits `4e43a802`/`fb7867b`) **except `families`**: across
  every serializer revision checked (2017 `74bab7f2`, 2019 `4e43a802`, 2022
  `fb7867b`, master), **`families` is never serialized into an entry**. It is
  verified only as (a) a `/api/v1/projects/` **filter parameter** and (b) the
  repo-"family" grouping concept (`PackageDataMinimal.family` in
  `repologyapp/package.py:183`). The fixture includes `families` per the
  assignment spec, flagged in its `_meta.json`; a real client must not expect
  it (parse with `#[serde(default)]` / ignore unknown keys).

`status` values (docs + `PackageStatus::as_string`,
`repologyapp/package.py:61-74`, exact set): `newest`, `outdated`, `ignored`,
`unique`, `devel`, `legacy`, `incorrect`, `untrusted`, `noscheme`, `rolling`.
(`ignored`/`incorrect`/`untrusted`/`noscheme`/`rolling` count as
"ignored-ish" per `is_ignored`, `package.py:52-58`.)

Envelope details (`api.py:66-70`): `Content-Type: application/json`;
pretty-printed **and key-sorted** when the server enables `PRETTY_JSON`,
compact otherwise — don't rely on key order or whitespace. A real-world
fedora_rawhide entry (Renovate discussion #26619) matches the master
serializer field-for-field, e.g. `"repo": "fedora_rawhide", "subrepo":
"development", "srcname": "ncurses", ... "status": "newest", "origversion":
"6.4-9.20240113.fc40"` with `licenses`, `summary`, `categories` — good model
for the fixture.

## 3. Name canonicalization — the alias-oracle role

Repology's core value for a registry client: many per-repo package names are
coalesced into one canonical **project** name.

- Docs (verbatim): *"Project has its own name which is derived from package
  names. In most cases it's the same, but sometimes different package names
  are transformed into a single project name to coalesce differently named
  packages from different repositories."*
- Mechanism: canonicalization is rule-driven (`repology/repology-rules` repo,
  verified to exist, default branch `master`) plus manual redirects; the
  canonical name surfaces in the DB as `metapackages.effname`
  (`sql.d/names/get_projects_by_name.sql`: `SELECT effname FROM metapackages
  WHERE id = project_id`), while per-repo spellings live in the
  `project_names` table keyed by `(repository_id, name_type, name)`.
  In-package aliases also exist: `srcname`, `binname`, `trackname`,
  `projectname_seed` (`repologyapp/package.py:200-214`).

Directions a client can use:

- **Canonical → per-repo names** (the "what do repos call this" lookup):
  `GET /api/v1/project/<canonical>` and read `srcname`/`binname` off the
  entries whose `repo` you care about. One request, no auth.
- **Per-repo name → canonical** (reverse): `GET
  /tools/project-by?repo=<repo>&name_type=<srcname|binname>&name=<name>&target_page=api_v1_project`
  (`views/tools.py:77-139`). Behavior, verbatim from code:
  - unknown repo or no match → **404** (`tools.py:95,106`);
  - match → **302** redirect to the chosen target (`tools.py:130`);
  - multiple matches + `noautoresolve` → **300** with JSON body
    `{"_comment": "Ambiguous redirect, multiple target projects are possible",
    "targets": {"<project>": "<url>", ...}}` (`tools.py:108-120`).
  - `name_type` options are exactly `srcname` and `binname`
    (`templates/tools/project-by.html:43-44`); which of the two a repo
    provides varies per repo (see `/repositories/fields`).
  - With `target_page=api_v1_project` the redirect lands on
    `/api/v1/project/<effname>` — i.e. a two-step alias resolution with no
    HTML scraping (`tools.py:65` declares it as an allowed JSON target).
- **Repo → repo name map** (bulk alternative to project-by):
  `GET /api/experimental/distromap?fromrepo=A&torepo=B` returns pairs of
  per-repo names; `expand=1` yields one-name-per-side pairs, `format=plaintext`
  a TSV-ish dump (`api.py:136-160`).

Client guidance for the fixture shape: project entries from one repo share
`name`/`srcname` but may differ in `binname` (e.g. `brave-browser` vs
`brave`), `origversion` carries the repo-native version suffix
(`1.79.126-1`), and `status` per entry — pick entries by `repo` first, then
prefer `srcname` for source-based repos and `binname` for binary-install
lookup.

## 4. Rate limits / fair use (client policy)

Verbatim from the docs template (`api.html`, "Terms of use"):

> Bulk requests to this API are discouraged, consider using a [database
> dump](https://dumps.repology.org/README.txt). Bulk clients must identify
> themselves with a custom user-agent, referring to a description of the
> client and a way to report misbehavior (such as GitHub repository with an
> issue tracker). Bulk clients must not do more than one request per second.
> Miscomplying clients will be blocked.

The live page (via server-side reader; text partially truncated in capture)
matches: *"Allowed request rate to the API is no more than 1 request per
second. Bulk (more than 1000 requests per day) requests to the API are
disco[uraged]…"* — same 1 rps allowance, quantified bulk threshold.

The same page also warns, verbatim: *"Note that API stability is currently not
guaranteed - it may change at any moment."*

Practical policy for the toride client:

1. ≤ 1 request/second sustained; treat 403/429 as "you were blocked, back off
   hard" (no documented retry-after semantics — the docs threaten blocking,
   not throttling).
2. Set a descriptive `User-Agent` (project + contact URL) — mandatory posture
   for anything resembling batch use.
3. Cache aggressively; single-project lookups (`/api/v1/project/<name>`) are
   the cheap path. For bulk sweeps use the dump at
   `https://dumps.repology.org/README.txt` instead of the API.
4. Parse tolerantly: no stability guarantee; optional fields come and go
   across eras (`name`, `keyname`, `www`, `downloads` history above);
   `families` never guaranteed.
5. `/tools/project-by` redirects are the sanctioned reverse lookup — but it is
   a redirect endpoint, so follow redirects and expect 300/302/404 rather than
   a plain 200 JSON body.

## 5. Fixture

`crates/toride-registry/tests/fixtures/repology/project-brave-browser.json` —
synthetic `/api/v1/project/brave-browser` response: JSON array of 5 entries
(`homebrew`, `debian_13`, `fedora_rawhide`, `arch`, `alpine_edge`), covering
statuses `newest`/`outdated`/`devel`, optional fields present and absent
(subrepo, binname, maintainers, categories, origversion), and `origversion`
≠ `version` (Debian/Fedora/Alpine suffixes). `project-brave-browser_meta.json`
records `{"synthetic": true, "reason": ...}` plus per-field provenance.
All repo IDs verified real (see §1); all values (versions, maintainers,
families count) are invented — in particular, official Debian/Fedora/Arch do
not actually ship brave-browser.

## 6. Sources

- `https://repology.org/api` — docs page text (captured via server-side web
  reader; sandbox itself blocked by DNS pinning to 127.0.0.1)
- `https://github.com/repology/repology-webapp/blob/master/repologyapp/templates/api.html` — docs template (mirrors the live page; quoted verbatim above)
- `https://github.com/repology/repology-webapp/blob/master/repologyapp/views/api.py` — routes + serializer (master; history at commits `74bab7f2` 2017, `4e43a802` 2019, `fb7867bc` 2022, `7efb88cb` 2023)
- `https://github.com/repology/repology-webapp/blob/master/repologyapp/views/tools.py` — `/tools/project-by`
- `https://github.com/repology/repology-webapp/blob/master/repologyapp/package.py` — `PackageStatus`/`PackageDataDetailed`
- `https://github.com/repology/repology-webapp/blob/master/repologyapp/views/legacy.py` — HTML `/metapackage/*` redirects
- `https://github.com/repology/repology-updater` — `repos.d/**` repo-ID configs; `https://github.com/repology/repology-rules` — name rules
- `https://github.com/renovatebot/renovate/discussions/26619` — real-world fedora_rawhide payload snippet (cross-check)
- `https://dumps.repology.org/README.txt` — bulk-dump alternative (link target quoted from docs; host not probed)
