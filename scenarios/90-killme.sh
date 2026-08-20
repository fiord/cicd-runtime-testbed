#!/usr/bin/env bash
#
# scenarios/90-killme.sh
#
# 用途:
#   .cicd-sensor/rules/testbed.yaml の `testbed_kill_marker` ルール
#   (action: terminate) だけを狙って発火させる、kill 発火専用スクリプト。
#   docs/SPEC.md 5節のとおり、このスクリプトは sensor-enforce.yml
#   からのみ呼ばれる想定。
#
# 安全性:
#   行なうのはローカルの一時ファイルへの書き込みのみ。実在の IOC は
#   使わない。cicd-sensor の kill テストは本スクリプト専用のカスタム
#   ルールでのみ発火させる。
#
# 期待される検知内容:
#   `.cicd-sensor/rules/testbed.yaml` の `testbed_kill_marker`
#   (event_type: file_open, is_write && path.endsWith
#   ("/cicd-sensor-killme.marker"), action: terminate) が発火し、
#   monitor_mode: false のジョブではプロセスが終了 (kill) される想定。
#
#   本スクリプトの直後に `echo "REACHED_AFTER_KILLME"` を実行する。
#   この文字列がジョブのログに出ていたら、kill されなかったことを
#   意味する (sensor-enforce.yml の assert ジョブがこれを判定に使う)。
#
# 注意 (docs/SPEC.md 5節): sensor-enforce.yml では、このシナリオ「だけ」
# は「kill されて enforce ジョブが失敗すること」が正常な結果である。
# 他のシナリオスクリプトと違い、「常に exit 0 で成功すること」を
# 目的とした設計ではない (kill された場合、このプロセスはシグナルで
# 終了するため、そもそも exit 0 まで到達しない)。
#
# 通常の共通ルールに合わせ set -uo pipefail を使う (set -e は使わない)。

set -uo pipefail

SCENARIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCENARIO_DIR}/lib/common.sh"

step "write kill marker file"
marker_path="${TESTBED_TMPDIR}/cicd-sensor-killme.marker"
echo "cicd-runtime-testbed kill trigger" > "${marker_path}"
note "wrote ${marker_path}; testbed_kill_marker rule should fire on this file_open(is_write) event"
end_step

# kill されなかった場合にのみここへ到達する。到達した場合、ログに
# この文字列が出ることで sensor-enforce.yml の assert ジョブが
# 「kill されなかった」ことを検出できる。
echo "REACHED_AFTER_KILLME"

exit 0
