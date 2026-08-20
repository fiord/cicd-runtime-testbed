#!/usr/bin/env bash
#
# scenarios/06-anti-forensics.sh
#
# 用途:
#   証跡削除 (anti-forensics) の再現。00-seed.sh が作った偽クレデンシャル
#   と、05-memfd-exec.sh が python3 に渡した実行ドライバスクリプトを削除する。
#
# 実装上の注記 (SPEC のギャップを埋めた箇所。05-memfd-exec.sh のヘッダにも
# 同じ注記あり):
#   docs/SPEC.md は「05 で実行したバイナリを削除する」とだけ書いており、
#   memfd 経由の fileless exec には本来ディスク上の実体がない。ここでは
#   05 が $TESTBED_TMPDIR/05-memfd-driver.py に残した「python3 に渡した
#   実行ドライバファイル」を削除対象とすることで、SPEC が意図する
#   「実行後にファイルが消え、falco の SHA256 計算が
#   `File does not exist anymore` になる」検証ができるようにしている。
#
# 安全性:
#   削除対象は 00-seed.sh / 05-memfd-exec.sh がこのリポジトリ内で作った
#   偽ファイルのみ。システムファイルやリポジトリのソースファイルには
#   触れない。
#
# 期待される検知内容:
#   cicd-sensor / falco の `file_remove` イベント。falco 側では、削除後に
#   実行済みバイナリのハッシュ計算を試みると `File does not exist
#   anymore` 相当の結果になることを確認する材料になる。
#
# docs/SPEC.md 4節の要件どおり: set -uo pipefail (set -e は使わない)、
# 終了コードは常に 0。

set -uo pipefail

SCENARIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCENARIO_DIR}/lib/common.sh"

load_canaries

step "remove fake credentials seeded by 00-seed.sh"
safe_run rm -f "${HOME}/.aws/credentials"
safe_run rm -f "${HOME}/.docker/config.json"
safe_run rm -f "${HOME}/.npmrc"
safe_run rm -rf "/tmp/${CANARY_PATH}"
end_step

step "remove the driver script executed in 05-memfd-exec.sh"
driver_path="${TESTBED_TMPDIR}/05-memfd-driver.py"
safe_run rm -f "${driver_path}"
note "removed ${driver_path}; a later hash lookup against this path should now find it missing"
end_step

exit 0
