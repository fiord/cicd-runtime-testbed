#!/usr/bin/env bash
#
# tools/scan-leaks.sh
#
# 用途:
#   canaries/canaries.env の各カナリア値が、指定したスキャン対象
#   ディレクトリ (通常は各ワークフローがアップロードした telemetry-*
#   アーティファクトを展開したディレクトリ) の配下に含まれていないかを
#   横断的に走査する。cicd-runtime-testbed の T3 (secret 漏洩検証) の
#   実測データ (leak-report.json) を作る。leak-scan.yml (担当外) から
#   呼び出される想定。
#
# 安全性:
#   読み取り専用。外部通信は一切行わない。カナリアの「実値」は
#   leak-report.json に書き込まない (canary_id のみを記録する)。
#   スキャナ自身の出力が新たな漏洩源になることを防ぐため。
#
# 除外 (docs/SPEC.md 3節「重要な実装上の注意」を厳守。除外を誤ると
# canaries/canaries.env 自身がヒットし、全カナリアが常に「漏洩」と
# 誤判定される):
#   - リポジトリのソースツリー (スキャン対象ディレクトリ配下に
#     ネストしたチェックアウトが含まれる場合に備え、`.git` を含む
#     パスをまるごと除外する)
#   - canaries/ ディレクトリ (カナリアの定義そのものが置かれている)
#   - tools/ ディレクトリ (このスクリプトと render-matrix.py 自身)
#   - スキャナ自身の出力ファイル (leak-report.json、任意のファイル名)
#
#   意図的に除外しないもの:
#   - `telemetry-manifest.txt` (collect-telemetry ジョブが書く、テレメトリ
#     収集結果の一覧。docs/SPEC.md §6)。カナリアの実値を含まないファイル
#     なので走査対象から除外する実害がなく、むしろ走査対象に含めておくことで
#     「後から何が収集できていた/いなかったか」を leak-report.json の
#     locations 経由で追跡できる (この観点であえて除外リストに入れていない)。
#
# 期待される検知内容:
#   検知シナリオではない。docs/SPEC.md 3節の「期待結果」列と、実際に
#   telemetry アーティファクト中にカナリア値が現れたかどうかを突き合わせる
#   ための素材 (leak-report.json) を作る。判定そのものは
#   tools/render-matrix.py が行なう。
#
# 二次走査: ランナー由来トークンのパターン検出 (findings とは別枠):
#   「capture.scap に GitHub 発行の本物のトークンが実際に入るのか」を
#   検証項目とするための走査。leak-scan は走査対象とは別の run で実行
#   されるため実値での照合はできず、次のパターンでのみ判定する:
#     - GitHub トークン: ghs_/ghp_/gho_/ghu_/ghr_ に続く英数字列
#     - JWT (ACTIONS_RUNTIME_TOKEN 等): eyJ で始まる base64url セグメントが
#       ドット区切りで3つ連なった形
#   検出した実値は findings と同様に leak-report.json へ絶対に書かない。
#   パターン種別・ヒット件数・ファイル名のみを、トップレベルキー
#   `runner_token_findings` として記録する (findings の構造は変えない)。
#   既知のカナリア値と一致する場合は除外する (偽の ghp_ 様カナリア値が
#   二重計上されるのを防ぐため)。この走査は「発見」であって「漏洩失敗の
#   判定」ではないため、tools/render-matrix.py 側の exit code には
#   影響させない。
#
# Usage:
#   tools/scan-leaks.sh <スキャン対象ディレクトリ> [出力ファイル]
#
# 出力:
#   leak-report.json (省略時はカレントディレクトリに作成)
#   トップレベルキー `scan_root` (走査対象ディレクトリの呼び出し時の引数
#   文字列) と `scanned_file_count` (実際に走査したファイル数) を含む。
#   これは tools/render-matrix.py が「走査対象 0 件 (＝テスト不成立)」を
#   期待と実測の乖離と区別して扱うために使う (docs/SPEC.md §7)。
#
#   `telemetry_dirs`: 走査対象ディレクトリの直下にあるディレクトリ名の
#   一覧 (例: ["telemetry-cicd-sensor-monitor"])。tools/render-matrix.py の
#   ツール種別判定 (`telemetry-cicd-sensor-*` → cicd-sensor、
#   `telemetry-falco-*` → falco) がこの走査時点のスナップショットを
#   優先的に使うことで、render-matrix.py を実行する時点で scan_root に
#   ファイルシステムアクセスできるかどうかに判定結果が左右されなくなる
#   (leak-report.json 単体で再現可能な判定にするため)。
#
# カナリア走査の大文字小文字非依存化 (実地実行 run 32381640678 で判明した
# 偽陰性の修正):
#   DNS 名は解決前にリゾルバによって小文字に正規化されるため、
#   CANARY_DNS (canaries.env 上は `CNRY-DNS-DONOTUSE-18ebf5`) は
#   attestation predicate の domains 配列には `cnry-dns-donotuse-18ebf5...`
#   として (小文字化・search domain 付加のうえ) 現れる。以前の実装は
#   `grep -aFo` (大文字小文字を区別する完全一致 *ではない* 部分一致) で、
#   `grep -c` では 0 件だったが `grep -ci` では 1 件ヒットすることを実測で
#   確認した。つまり実際には漏れていたのに見逃していた (偽陰性)。
#   これを修正するため、カナリア本走査は `grep -aFio` (大文字小文字非依存の
#   固定文字列・部分一致) に変更した。カナリア値は `CNRY` + 一意な英数字の
#   組み合わせで構成されており、大文字小文字を無視しても他の文字列との
#   衝突・誤検出の可能性は極めて低いため、全カナリアにこの変更を適用してよい
#   と判断した。マッチが大文字小文字非依存で行なわれたことは、
#   leak-report.json のトップレベルキー `canary_match_mode` にも明記する
#   (この節と合わせて二重に記録することで、後から leak-report.json だけを
#   読む場合でも判定条件が分かるようにする)。
#
#   なお「部分一致で拾えている (完全一致を要求していない) か」も実測で
#   確認済み: `grep -aFo -- "${value}" "${f}"` は行全体一致ではなく
#   部分文字列一致であり、DNS ラベルに付加される resolver の search domain
#   (`.zuup3ixw3die3n0bckkvpevybe.bx.internal.cloudapp.net` 等) が後ろに
#   付いていても正しくヒットする。この挙動は変更していない。
#
#   一方で `runner_token_findings` (二次走査、下記) は**意図的に**大文字
#   小文字を区別したままにしている。`ghs_`/`ghp_`/`gho_`/`ghu_`/`ghr_`
#   といった GitHub トークンのプレフィックスや JWT の `eyJ` は仕様上すべて
#   小文字・大文字が固定されており意味を持つため、非依存にすると
#   (例えば大文字小文字を無視した結果、無関係な文字列を誤ってトークン
#   らしきものとして拾ってしまう等) 誤検出が増えるだけでメリットがない。
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CANARIES_FILE="${REPO_ROOT}/canaries/canaries.env"

TARGET_DIR="${1:-}"
OUTPUT_FILE="${2:-leak-report.json}"

if [ -z "${TARGET_DIR}" ]; then
  echo "usage: $0 <scan-target-dir> [output-file]" >&2
  exit 1
fi

if [ ! -d "${TARGET_DIR}" ]; then
  echo "error: scan target directory not found: ${TARGET_DIR}" >&2
  exit 1
fi

if [ ! -f "${CANARIES_FILE}" ]; then
  echo "error: canaries file not found: ${CANARIES_FILE}" >&2
  exit 1
fi

# leak-report.json に記録する scan_root は、呼び出し元がそのまま渡した
# 引数の文字列を使う (絶対パスに解決したあとの値ではない)。ディレクトリ名
# そのものに秘密情報が混入することは通常ないが、念のため値そのもの
# (カナリア値やトークン等) ではなく単なるパス表記であることを前提にする。
SCAN_ROOT_LABEL="${TARGET_DIR}"

TARGET_DIR="$(cd "${TARGET_DIR}" && pwd)"

case "${OUTPUT_FILE}" in
  /*) : ;;
  *) OUTPUT_FILE="$(pwd)/${OUTPUT_FILE}" ;;
esac
OUTPUT_BASENAME="$(basename "${OUTPUT_FILE}")"

# --- canary_id -> expected result ("leak" / "no_leak") ----------------
# docs/SPEC.md 3節の「期待結果」列と同じ。
#
# 注記 (SPEC に明記のない簡略化): CANARY_SCAP は「falco の capture.scap
# でのみ漏れる」という条件付きの期待結果を持つが、この found/no_leak の
# 二値モデルではその条件を直接表現できない。ここでは SPEC の文中にある
# 「漏れる」という動詞に合わせて expected=leak とし、条件の細部は
# render-matrix.py 側の注記と leak-report.json の locations[] を見て
# 人間が判断する設計にした。
declare -A EXPECTED=(
  [CANARY_ENV]=no_leak
  [CANARY_FILE]=no_leak
  [CANARY_PATH]=leak
  [CANARY_ARGV_SHORT]=leak
  [CANARY_ARGV_LONG]=no_leak
  [CANARY_ARGV_FLAG]=no_leak
  [CANARY_URL_QUERY]=no_leak
  [CANARY_URL_PATH]=leak
  [CANARY_DNS]=leak
  [CANARY_SCAP]=leak
)

# --- load canaries -------------------------------------------------------
# shellcheck source=/dev/null
source "${CANARIES_FILE}"

# --- collect candidate files, excluding repo source tree ------------------
# "リポジトリのソースツリー" 除外は、単に `.git` ディレクトリ自体を
# 取り除くだけでは不十分 (`.git` の隣にある README.md 等の兄弟ファイルが
# 除外されずに残ってしまう)。ここでは `.git` を持つディレクトリを
# "リポジトリルート" とみなし、そのディレクトリ配下をまるごと除外する。
mapfile -d '' REPO_ROOTS < <(
  find "${TARGET_DIR}" -type d -name '.git' -printf '%h\0' 2>/dev/null
)

prune_expr=(-path '*/canaries' -o -path '*/tools')
for repo_root in "${REPO_ROOTS[@]}"; do
  prune_expr+=(-o -path "${repo_root}")
done

mapfile -d '' CANDIDATE_FILES < <(
  find "${TARGET_DIR}" \
    \( "${prune_expr[@]}" \) -prune -o \
    -type f -not -name "${OUTPUT_BASENAME}" -print0
)

# --- scan --------------------------------------------------------------
canary_ids=()
for key in "${!EXPECTED[@]}"; do
  canary_ids+=("${key}")
done
IFS=$'\n' canary_ids=($(sort <<<"${canary_ids[*]}"))
unset IFS

FINDINGS_TMP="$(mktemp)"
TOKEN_FINDINGS_TMP="$(mktemp)"
trap 'rm -f "${FINDINGS_TMP}" "${TOKEN_FINDINGS_TMP}"' EXIT

echo "[" > "${FINDINGS_TMP}"
first_finding=1

for canary_id in "${canary_ids[@]}"; do
  value="${!canary_id:-}"
  expected="${EXPECTED[$canary_id]}"
  found="false"
  locations_json="[]"

  if [ -n "${value}" ] && [ "${#CANDIDATE_FILES[@]}" -gt 0 ]; then
    loc_entries=()
    for f in "${CANDIDATE_FILES[@]}"; do
      # -a: バイナリファイル (capture.scap 等) もテキストとして扱って
      # 検索する。-F: 固定文字列検索 (正規表現メタ文字を無視)。
      # -i: 大文字小文字を区別しない (DNS 名は小文字に正規化されるため。
      # スクリプト冒頭のコメント参照。実地実行 run 32381640678 で判明した
      # 偽陰性の修正)。
      # -o: マッチ箇所ごとに1行出力するので wc -l で出現回数になる。
      count="$(grep -aFio -- "${value}" "${f}" 2>/dev/null | wc -l | tr -d ' ')"
      if [ -n "${count}" ] && [ "${count}" -gt 0 ]; then
        found="true"
        rel="${f#"${TARGET_DIR}"/}"
        esc_rel="${rel//\\/\\\\}"
        esc_rel="${esc_rel//\"/\\\"}"
        loc_entries+=("{\"file\": \"${esc_rel}\", \"count\": ${count}}")
      fi
    done
    if [ "${#loc_entries[@]}" -gt 0 ]; then
      locations_json="[$(IFS=,; echo "${loc_entries[*]}")]"
    fi
  elif [ -z "${value}" ]; then
    # CANARY_ENV は GitHub Secret 未設定の場合に空になり得る
    # (docs/SPEC.md 3節)。値が空なら検索しようがないので found=false のまま
    # 記録する。
    :
  fi

  if [ "${first_finding}" -eq 0 ]; then
    echo "," >> "${FINDINGS_TMP}"
  fi
  first_finding=0
  cat >> "${FINDINGS_TMP}" <<EOF
  {
    "canary_id": "${canary_id}",
    "expected": "${expected}",
    "found": ${found},
    "locations": ${locations_json}
  }
EOF
done
echo "]" >> "${FINDINGS_TMP}"

# --- secondary scan: runner-issued token patterns (independent of canaries) --
# 既存のカナリア走査 (実値の完全一致) とは別枠。ここでは実値ではなく
# パターンでランナー発行トークンらしき文字列を探す (スクリプト冒頭コメント
# 参照)。除外対象 (CANDIDATE_FILES) と「実値を書かない」原則は上と共通。
declare -A TOKEN_PATTERNS=(
  [github_token]='gh[psoru]_[A-Za-z0-9]{20,255}'
  [jwt]='eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
)
token_pattern_ids=(github_token jwt)

# 既知のカナリア値一覧 (偽の ghp_ 様の値等が二重計上されるのを防ぐための
# 除外リスト)。
CANARY_VALUES=()
for canary_id in "${canary_ids[@]}"; do
  v="${!canary_id:-}"
  if [ -n "${v}" ]; then
    CANARY_VALUES+=("${v}")
  fi
done

is_known_canary_value() {
  local candidate="$1"
  local kv
  for kv in "${CANARY_VALUES[@]}"; do
    if [ "${candidate}" = "${kv}" ]; then
      return 0
    fi
  done
  return 1
}

echo "[" > "${TOKEN_FINDINGS_TMP}"
first_token_finding=1

for pattern_id in "${token_pattern_ids[@]}"; do
  pattern="${TOKEN_PATTERNS[${pattern_id}]}"
  total_count=0
  loc_entries=()

  if [ "${#CANDIDATE_FILES[@]}" -gt 0 ]; then
    for f in "${CANDIDATE_FILES[@]}"; do
      # -a: バイナリファイルもテキストとして扱う。-E: 拡張正規表現。
      # -o: マッチ箇所ごとに1行出力 (実値をここで変数に読み込むが、
      # ファイルには一切書き出さない。件数のみを記録する)。
      mapfile -t matches < <(grep -aEo -- "${pattern}" "${f}" 2>/dev/null || true)
      file_count=0
      for m in "${matches[@]}"; do
        [ -z "${m}" ] && continue
        if ! is_known_canary_value "${m}"; then
          file_count=$((file_count + 1))
        fi
      done
      if [ "${file_count}" -gt 0 ]; then
        rel="${f#"${TARGET_DIR}"/}"
        esc_rel="${rel//\\/\\\\}"
        esc_rel="${esc_rel//\"/\\\"}"
        loc_entries+=("{\"file\": \"${esc_rel}\", \"count\": ${file_count}}")
        total_count=$((total_count + file_count))
      fi
    done
  fi

  locations_json="[]"
  if [ "${#loc_entries[@]}" -gt 0 ]; then
    locations_json="[$(IFS=,; echo "${loc_entries[*]}")]"
  fi

  if [ "${first_token_finding}" -eq 0 ]; then
    echo "," >> "${TOKEN_FINDINGS_TMP}"
  fi
  first_token_finding=0
  cat >> "${TOKEN_FINDINGS_TMP}" <<EOF
  {
    "pattern": "${pattern_id}",
    "count": ${total_count},
    "locations": ${locations_json}
  }
EOF
done
echo "]" >> "${TOKEN_FINDINGS_TMP}"

scanned_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# leak-scan.yml は「走査対象にした run」の ID を SCANNED_RUN_ID として渡す
# (自分自身の run である GITHUB_RUN_ID とは別物: leak-scan.yml 自身の
# run_id ではなく、telemetry-* アーティファクトの出所である対象 run を
# leak-report.json に記録したいため、SCANNED_RUN_ID を優先する)。
run_id="${SCANNED_RUN_ID:-${GITHUB_RUN_ID:-unknown}}"

# render-matrix.py が「走査対象 0 件」(＝テスト不成立) を独立したエラーと
# して扱えるように、実際に走査したファイル数と走査対象ディレクトリを
# トップレベルに記録する。scan_root は上で保持した呼び出し時の引数文字列
# (パス表記のみ。値そのものは含まない)。
scanned_file_count="${#CANDIDATE_FILES[@]}"
scan_root_escaped="${SCAN_ROOT_LABEL//\\/\\\\}"
scan_root_escaped="${scan_root_escaped//\"/\\\"}"

# telemetry_dirs: 走査対象ディレクトリ (TARGET_DIR) の直下にあるディレクトリ
# 名の一覧。render-matrix.py のツール種別判定 (present_tools) がこれを
# 優先して使う (スクリプト冒頭コメント参照)。
mapfile -d '' TELEMETRY_DIR_NAMES < <(
  find "${TARGET_DIR}" -mindepth 1 -maxdepth 1 -type d -printf '%f\0' 2>/dev/null | sort -z
)
telemetry_dirs_entries=()
for d in "${TELEMETRY_DIR_NAMES[@]}"; do
  esc_d="${d//\\/\\\\}"
  esc_d="${esc_d//\"/\\\"}"
  telemetry_dirs_entries+=("\"${esc_d}\"")
done
telemetry_dirs_json="[]"
if [ "${#telemetry_dirs_entries[@]}" -gt 0 ]; then
  telemetry_dirs_json="[$(IFS=,; echo "${telemetry_dirs_entries[*]}")]"
fi

{
  echo "{"
  echo "  \"scanned_at\": \"${scanned_at}\","
  echo "  \"run_id\": \"${run_id}\","
  echo "  \"scan_root\": \"${scan_root_escaped}\","
  echo "  \"telemetry_dirs\": ${telemetry_dirs_json},"
  echo "  \"scanned_file_count\": ${scanned_file_count},"
  # findings (カナリア本走査) は大文字小文字非依存 (grep -aFio) で行なわれた
  # ことを明記する (スクリプト冒頭のコメント参照。run 32381640678 で判明した
  # 偽陰性の再発防止)。runner_token_findings (二次走査) は対象外で、
  # 引き続き大文字小文字を区別する。
  echo "  \"canary_match_mode\": \"case_insensitive\","
  echo "  \"findings\": $(cat "${FINDINGS_TMP}"),"
  echo "  \"runner_token_findings\": $(cat "${TOKEN_FINDINGS_TMP}")"
  echo "}"
} > "${OUTPUT_FILE}"

echo "leak scan complete: ${OUTPUT_FILE}" >&2
exit 0
