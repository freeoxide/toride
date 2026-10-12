#!/usr/bin/env bash
# check_plan_citations.sh — mechanical gate for docs/setup-bundles-plan.md.
#
# READ-ONLY: never writes a file. Deps: bash + grep + awk + sed + wc only.
# Path-independent: resolves the repo root from this script's location.
#
# Exits 1, naming the offender, when:
#   (a) any `crates/*.rs:LINE` or `crates/*.toml:LINE` citation in the plan
#       points at a missing file or a line beyond EOF;
#   (b) the license table is missing any required tool row
#       (sccache mold orbstack docker colima podman uv opentofu terraform);
#   (c) any license-table data row lacks a https:// URL;
#   (d) a required section header is missing
#       (Goal, Survey, Decision, API, Phases/Milestones, Test plan, Risks);
#   (e) docs/setup-bundles-plan.md is missing/empty, or this script was
#       truncated (see the EXIT trap below — the one form bash cannot catch
#       is a file cut down to the shebang or emptied entirely, which exits 0
#       as a no-op; callers should treat the summary line as the success
#       signature).
# On success prints:
#   check_plan_citations: N citations OK, M license rows OK

set -u

# Truncation guard for check (e): every legitimate exit path either fails
# explicitly (non-zero rc — the trap keeps it) or reaches the final summary
# (which sets done=1). A script cut anywhere below this line therefore exits
# non-zero instead of silently succeeding.
done=0
trap 'rc=$?; [ "$rc" -ne 0 ] && exit 1; [ "$done" -eq 1 ] || { printf "check_plan_citations: FAIL: scripts/check_plan_citations.sh is truncated (exited before the summary line)\n" >&2; exit 1; }' EXIT

root="$(cd "$(dirname "$0")/.." && pwd)"
plan="$root/docs/setup-bundles-plan.md"
self="$root/scripts/check_plan_citations.sh"

fail() {
    printf 'check_plan_citations: FAIL: %s\n' "$1" >&2
    exit 1
}

# (e) emptiness / script integrity ---------------------------------------------
[ -s "$plan" ] || fail "docs/setup-bundles-plan.md is missing or empty"
[ -s "$self" ] || fail "scripts/check_plan_citations.sh is empty"
grep -q 'check_plan_citations: %d citations OK' "$self" \
    || fail "scripts/check_plan_citations.sh is truncated or corrupted (sentinel missing)"

# (d) required section headers ---------------------------------------------------
section_ok() {
    grep -Eqi "^#+.*$1" "$plan"
}
section_ok 'goal'            || fail "required section missing: Goal"
section_ok 'survey'          || fail "required section missing: Survey"
section_ok 'decision'        || fail "required section missing: Decision"
section_ok 'api'             || fail "required section missing: API"
section_ok 'phase|milestone' || fail "required section missing: Phases/Milestones"
section_ok 'test plan'       || fail "required section missing: Test plan"
section_ok 'risk'            || fail "required section missing: Risks"

# (a) citation resolution ----------------------------------------------------------
# Citation shape: crates/<path>.rs:LINE or crates/<path>.toml:LINE anywhere in
# the plan (prose, tables, code sketches). Deduped; every occurrence checked.
citations=0
while IFS= read -r cite; do
    [ -n "$cite" ] || continue
    rel="${cite%:*}"
    line="${cite##*:}"
    path="$root/$rel"
    if [ ! -f "$path" ]; then
        fail "citation references a missing file: $rel (citation $cite)"
    fi
    # Exact line-existence test: sed prints line $line; grep -q '' is true
    # only when at least one line of input arrived (works for empty lines,
    # and for files whose last line lacks a trailing newline).
    if ! sed -n "${line}p" "$path" | grep -q ''; then
        eof="$(wc -l < "$path" | tr -d ' ')"
        fail "citation line $line is beyond EOF ($eof lines) in $rel (citation $cite)"
    fi
    citations=$((citations + 1))
done < <(grep -oE 'crates/[A-Za-z0-9_./-]+\.(rs|toml):[0-9]+' "$plan" | sort -u)

[ "$citations" -gt 0 ] || fail "plan contains no crates/*.rs|toml:LINE citations at all"

# License table rows: scoped to the section whose header contains
# "license table"; separator rows and the column-header row are dropped.
license_rows() {
    awk '
        /^[[:space:]]*#+.*[Ll]icense[[:space:]]+table/ { insec = 1; next }
        insec && /^[[:space:]]*#/                      { insec = 0; next }
        insec && /^[[:space:]]*\|/                     { print }
    ' "$plan" \
        | grep -Ev '^[[:space:]]*\|[[:space:]]*[-:]' \
        | grep -Eiv '^[[:space:]]*\|[[:space:]]*tool[[:space:]]*\|'
}

# (c) every license-table data row carries a URL ------------------------------------
rows=0
while IFS= read -r row; do
    [ -n "$row" ] || continue
    case "$row" in
        *https://*) ;;
        *) fail "license table row lacks a terms URL: $row" ;;
    esac
    rows=$((rows + 1))
done < <(license_rows)

[ "$rows" -gt 0 ] || fail "license table section has no data rows (is the 'license table' header present?)"

# (b) required tool rows -------------------------------------------------------------
# A row "matches" a tool when the row's first cell begins with the tool name
# (case-insensitive), so `| Docker Desktop (docker-desktop) |` covers docker
# and prose mentions elsewhere in the plan do not count.
for tool in sccache mold orbstack docker colima podman uv opentofu terraform; do
    license_rows | grep -Eiq "^[[:space:]]*\|[[:space:]]*${tool}" \
        || fail "license table is missing the required tool row: $tool"
done

done=1
printf 'check_plan_citations: %d citations OK, %d license rows OK\n' "$citations" "$rows"
