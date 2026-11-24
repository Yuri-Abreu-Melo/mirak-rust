#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)_$$"
VULS_CONFIG="${VULS_CONFIG:-/home/vagrant/config.toml}"
VULS_RESULTS_ROOT="${VULS_RESULTS_ROOT:-/opt/vuls/results}"
VULS_RUN_RESULTS_DIR="${VULS_RESULTS_ROOT%/}/${RUN_ID}"
VULS_REPORT_DIR="${VULS_REPORT_DIR:-${SCRIPT_DIR}/vuls-reports/${RUN_ID}}"

run_as_root() {
  if [[ "${EUID}" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

fail() {
  echo "[ERROR] $*" >&2
  exit 1
}

command -v jq >/dev/null 2>&1 || fail "jq is required. Install it with the system package manager."
VULS_BIN="$(command -v vuls || true)"
[[ -n "$VULS_BIN" ]] || fail "The vuls executable was not found in PATH."
[[ -r "$VULS_CONFIG" ]] || fail "Vuls config file is not readable: $VULS_CONFIG"

if [[ "${EUID}" -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 || fail "sudo is required to run a local Vuls scan."
  sudo -v
fi

mkdir -p "$VULS_REPORT_DIR"
run_as_root mkdir -p "$VULS_RUN_RESULTS_DIR"

echo "============================================================"
echo "Vuls Local Scan and Routinator/Fort Vulnerability Check"
echo "Host: $(hostname)"
echo "Config: $VULS_CONFIG"
echo "Reports: $VULS_REPORT_DIR"
echo "============================================================"

echo "[1/3] Running Vuls scan for localhost..."
if ! run_as_root "$VULS_BIN" scan \
  "-config=$VULS_CONFIG" \
  "-results-dir=$VULS_RUN_RESULTS_DIR" \
  localhost >"$VULS_REPORT_DIR/vuls_scan.log" 2>&1; then
  tail -n 40 "$VULS_REPORT_DIR/vuls_scan.log" >&2
  fail "Vuls scan failed. Full log: $VULS_REPORT_DIR/vuls_scan.log"
fi

echo "[2/3] Generating JSON and full-text reports..."
if ! run_as_root "$VULS_BIN" report \
  "-config=$VULS_CONFIG" \
  "-results-dir=$VULS_RUN_RESULTS_DIR" \
  -format-json \
  -format-full-text \
  -to-localfile >"$VULS_REPORT_DIR/vuls_report.log" 2>&1; then
  tail -n 40 "$VULS_REPORT_DIR/vuls_report.log" >&2
  fail "Vuls report generation failed. Full log: $VULS_REPORT_DIR/vuls_report.log"
fi

JSON_SOURCE="$(run_as_root find "$VULS_RUN_RESULTS_DIR" -type f -name 'localhost.json' -print -quit)"
[[ -n "$JSON_SOURCE" ]] || fail "Vuls did not create localhost.json under $VULS_RUN_RESULTS_DIR."

TEXT_SOURCE="${JSON_SOURCE%.json}_full.txt"
[[ -f "$TEXT_SOURCE" ]] || fail "Vuls did not create the full-text report: $TEXT_SOURCE"

JSON_REPORT="$VULS_REPORT_DIR/vuls_report.json"
TEXT_REPORT="$VULS_REPORT_DIR/vuls_full_report.txt"
run_as_root install -m 0644 "$JSON_SOURCE" "$JSON_REPORT"
run_as_root install -m 0644 "$TEXT_SOURCE" "$TEXT_REPORT"

jq -e 'type == "object" and .serverName == "localhost" and has("scannedCves")' \
  "$JSON_REPORT" >/dev/null || fail "The generated Vuls JSON has an unexpected format."

MATCHES_FILE="$VULS_REPORT_DIR/validator_vulnerability_matches.tsv"
jq -r '
  def cve_metadata_text:
    [
      (.cveContents // {} | .. | objects | (.title? // empty)),
      (.cveContents // {} | .. | objects | (.summary? // empty))
    ]
    | map(select(type == "string"))
    | join(" ")
    | ascii_downcase;

  def has_routinator:
    any(.affectedPackages[]?;
      ((.name // "") | ascii_downcase | sub(":.*$"; "") == "routinator"))
    or any(.cpeURIs[]?; ascii_downcase | contains("routinator"))
    or (cve_metadata_text | test("(^|[^a-z0-9])routinator([^a-z0-9]|$)"));

  def has_fort_validator:
    any(.affectedPackages[]?;
      ((.name // "") | ascii_downcase | sub(":.*$"; "")
        | test("^(fort|fort-validator|fort_validator)$")))
    or any(.cpeURIs[]?;
      (ascii_downcase
        | test("(^|[:/])((nicmx:)?fort[-_]validator|fort)(:|/|$)")))
    or (cve_metadata_text | test("(^|[^a-z0-9])fort[- ]validator([^a-z0-9]|$)"));

  def target_products:
    [if has_routinator then "Routinator" else empty end,
     if has_fort_validator then "Fort Validator" else empty end];

  (.scannedCves // {})
  | to_entries[]
  | . as $entry
  | $entry.value as $vulnerability
  | ($vulnerability | target_products[]) as $product
  | [
      $product,
      $entry.key,
      ($vulnerability.affectedPackages // []
        | map(.name // "")
        | map(select(length > 0))
        | unique
        | join(", "))
    ]
  | @tsv
' "$JSON_REPORT" >"$MATCHES_FILE"

echo "[3/3] Checking CVEs associated with Routinator and Fort Validator..."
if [[ -s "$MATCHES_FILE" ]]; then
  while IFS=$'\t' read -r product cve packages; do
    if [[ -n "$packages" ]]; then
      printf "[VULNERABILITY FOUND] %s | %s | affected package(s): %s\n" \
        "$product" "$cve" "$packages"
    else
      printf "[VULNERABILITY FOUND] %s | %s | matched by Vuls CPE/CVE metadata\n" \
        "$product" "$cve"
    fi
  done <"$MATCHES_FILE"
else
  echo "[NO MATCH] Vuls reported no CVEs specifically associated with Routinator or Fort Validator."
fi

echo "[INFO] JSON report: $JSON_REPORT"
echo "[INFO] Full-text report: $TEXT_REPORT"
echo "[INFO] Scan log: $VULS_REPORT_DIR/vuls_scan.log"
echo "[NOTE] No matching result does not prove that a validator is vulnerability-free; Vuls only reports issues it can associate with its scanned packages or CPE metadata."
