#!/usr/bin/env bash
#
# scenarios/lib/common.sh
#
# 用途:
#   scenarios/*.sh から source される共通関数を提供する。カナリア読み込み、
#   GitHub Actions ログのグループ化、実行ログ (JSONL) への記録、失敗を
#   許容したコマンド実行のラッパを1箇所にまとめる。
#
# 安全性:
#   このファイル自体は外部通信を行わない。ここで定義する関数はすべて
#   ローカルのファイル操作とログ出力のみを行なう。
#
# 期待される検知内容:
#   このファイル自体は検知対象の操作を行わない (検知シナリオではない)。
#   scenarios/*.sh から source されて使われる土台。
#
# Usage (呼び出し側の先頭で):
#   # shellcheck source=lib/common.sh
#   source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"
#
# 提供する関数 (docs/SPEC.md 4節の表と同じ):
#   load_canaries        canaries/canaries.env を source する
#   step <name>          ログのグループ開始 + 実行中シナリオ名の記録
#   end_step              ログのグループ終了 (::endgroup::)
#   note <msg>            実行した操作を $TESTBED_LOG (JSONL) に記録する
#   safe_run <cmd...>     失敗を許容してコマンドを実行し、終了コードを記録
#
# このファイルは `set -uo pipefail` を前提に書かれている。source する側の
# スクリプトも同じ設定であること (`set -e` は使わない)。

# --- パス解決 ---------------------------------------------------------
# scenarios/lib/common.sh から見たリポジトリルート
TESTBED_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTBED_REPO_ROOT="$(cd "${TESTBED_LIB_DIR}/../.." && pwd)"
TESTBED_CANARIES_FILE="${TESTBED_REPO_ROOT}/canaries/canaries.env"

# --- 共通の一時ディレクトリ ---------------------------------------------
# 00-seed.sh / 05-memfd-exec.sh / 06-anti-forensics.sh のように、別々の
# ステップ (別プロセス) として実行されるスクリプト間で同じ一時ファイルを
# 参照し続けたい場合があるため、乱数を使わない固定パスにしている。
#
# なぜ $RUNNER_TEMP ではなく /var/tmp なのか (docs/REQUIRED-FIXES.md R-3):
#   GitHub-hosted runner の $RUNNER_TEMP は /home/runner/work/_temp に
#   解決される。falco の CI/CD ルール "Source Code Overwrite" は
#     open_write and fd.directory startswith "/home/runner/work/"
#   で発火し、その例外は proc.exepath が Runner.Worker の場合のみである。
#   ハーネス自身 (bash) が $RUNNER_TEMP 配下に一時ファイルや実行ログを
#   書くと、この例外に当たらず**テストハーネス自身の書き込みが
#   毎回アラートになる**。実測では falco-live の全アラート 240 件のうち
#   213 件がこれで、シナリオが起こした事象を評価できない状態だった。
#
#   これは「falco 側のルールを緩める」のではなく**ハーネス側を
#   ワークスペース外に退避させる**修正である点が重要で、
#   ツール中立である:
#     - falco  : ハーネスの自己ノイズが消え、シナリオ由来の
#                書き込みだけが残る。ルールには一切手を入れていない。
#     - cicd-sensor: testbed.yaml のルールは path.endsWith(<basename>)
#                で照合しており、ディレクトリを問わない。よって
#                発火条件は変わらない。
#
#   /var/tmp を選んだ理由: /tmp と違い systemd-tmpfiles の短期削除の
#   対象になりにくく、GitHub-hosted runner ではジョブ全体を通じて
#   存続し、かつワークスペース (/home/runner/work) の外にある。
: "${TESTBED_TMPDIR:=/var/tmp/cicd-runtime-testbed}"
mkdir -p "${TESTBED_TMPDIR}" 2>/dev/null || true
export TESTBED_TMPDIR

# --- 実行ログ (JSONL) ----------------------------------------------------
# $TESTBED_TMPDIR と同じ理由でワークスペース外に置く (上のコメント参照)。
# ワークフローがアーティファクトに収集するときは、この既定値ではなく
# 環境変数 $TESTBED_LOG を参照すること。
: "${TESTBED_LOG:=${TESTBED_TMPDIR}/testbed-log.jsonl}"
export TESTBED_LOG

# 現在実行中のステップ名 (note() が参照する)
TESTBED_CURRENT_STEP="${TESTBED_CURRENT_STEP:-}"

# JSON 文字列として安全に埋め込めるようにエスケープする。
# 引数: 生の文字列
# 標準出力: ダブルクォートを含まないエスケープ済み文字列
_testbed_json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  # 改行はJSONLの1行を壊すため空白に潰す
  s="${s//$'\n'/ }"
  s="${s//$'\r'/ }"
  printf '%s' "${s}"
}

# _testbed_redact_canaries <string>
#   現在シェルにロードされている CANARY_* 変数の「実値」が引数の文字列中に
#   含まれていれば <REDACTED:変数名> に置き換えて返す。
#
#   なぜ必要か: safe_run は実行したコマンド文字列 ("$*") をそのまま
#   note() 経由で $TESTBED_LOG (JSONL) に書く。このログは
#   falco-live.yml / falco-analyze.yml / sensor-monitor.yml /
#   sensor-enforce.yml の「Collect telemetry」ステップで
#   telemetry-*/testbed-log.jsonl としてそのままアーティファクトに
#   コピーされ、tools/scan-leaks.sh の走査対象になる (docs/SPEC.md 6-7節)。
#   02-exfil.sh のように、コマンドライン中にカナリアの実値をそのまま
#   展開して渡すシナリオ (例: CANARY_URL_QUERY, CANARY_ARGV_FLAG) では、
#   redaction せずにログへ書くと、falco/cicd-sensor 自体が漏らしたわけ
#   ではないのに「テストベッド自身の実行ログ」経由でカナリアが見えて
#   しまい、docs/SPEC.md 3節の期待結果 (漏れない) を自己成就的に破って
#   しまう (T3 の判定が汚染される)。ここで一律に redact することで、
#   leak-report.json / render-matrix.py が見る「漏洩」は実際にツール側の
#   経路で漏れたものだけになる。
_testbed_redact_canaries() {
  local s="$1"
  local var val
  for var in $(compgen -v | grep '^CANARY_'); do
    val="${!var:-}"
    if [ -n "${val}" ]; then
      s="${s//${val}/<REDACTED:${var}>}"
    fi
  done
  printf '%s' "${s}"
}

# load_canaries
#   canaries/canaries.env を source し、CANARY_* 変数を現在のシェルに
#   展開する。CANARY_ENV がジョブ環境にまだ来ていない (Secret 未設定) 場合は
#   その旨を note() で記録し、canaries.env のフォールバック値で処理を続ける。
load_canaries() {
  if [ ! -f "${TESTBED_CANARIES_FILE}" ]; then
    echo "::error::canaries file not found: ${TESTBED_CANARIES_FILE}" >&2
    return 0
  fi

  local env_before="${CANARY_ENV:-}"

  # shellcheck source=/dev/null
  source "${TESTBED_CANARIES_FILE}"

  if [ -z "${env_before}" ]; then
    note "CANARY_ENV secret not present in job env before load_canaries (GitHub Secret likely unset); falling back to canaries.env value. The env-var leak path (T3) is not meaningfully exercised this run."
  fi
}

# step <name>
#   GitHub Actions のログをグループ化し (::group::)、実行中のシナリオ名を
#   記録する。対応する end_step を必ず呼ぶこと。
step() {
  local name="${1:-unnamed-step}"
  TESTBED_CURRENT_STEP="${name}"
  echo "::group::${name}"
  note "step started: ${name}"
}

# end_step
#   step で開始したログのグループを終了する (::endgroup::)。
end_step() {
  note "step finished: ${TESTBED_CURRENT_STEP}"
  echo "::endgroup::"
}

# note <msg>
#   実行した操作を $TESTBED_LOG (JSONL, 1行1JSON) に追記する。
#   カナリアの実値そのものを引数に渡さないこと (この関数はメッセージを
#   そのまま記録するので、呼び出し側で値を含めないよう注意する)。
note() {
  local msg="${1:-}"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local esc_step esc_msg
  esc_step="$(_testbed_json_escape "${TESTBED_CURRENT_STEP}")"
  esc_msg="$(_testbed_json_escape "${msg}")"
  printf '{"ts": "%s", "step": "%s", "msg": "%s"}\n' \
    "${ts}" "${esc_step}" "${esc_msg}" >> "${TESTBED_LOG}"
}

# safe_run <cmd...>
#   失敗を許容してコマンドを実行する。終了コードを note() に記録し、
#   safe_run 自体は常に 0 を返す (呼び出し元スクリプトを止めないため)。
#   `set -e` は使わない前提だが、safe_run を通すことで失敗が
#   ログ上に明示的に残る。
safe_run() {
  if [ "$#" -eq 0 ]; then
    note "safe_run called with no command"
    return 0
  fi

  local cmd_str="$*"
  local rc=0
  "$@" || rc=$?

  # ログに残すコマンド文字列からはカナリアの実値を redact する
  # (理由は _testbed_redact_canaries のコメントを参照)。
  local logged_cmd_str
  logged_cmd_str="$(_testbed_redact_canaries "${cmd_str}")"

  if [ "${rc}" -eq 0 ]; then
    note "safe_run ok (rc=0): ${logged_cmd_str}"
  else
    note "safe_run failed (rc=${rc}): ${logged_cmd_str}"
  fi
  return 0
}
