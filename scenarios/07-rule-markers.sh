#!/usr/bin/env bash
#
# scenarios/07-rule-markers.sh
#
# 用途:
#   .cicd-sensor/rules/testbed.yaml の testbed_detect_marker
#   (action: detect) と testbed_collect_marker (action: collect) を発火
#   させる専用スクリプト。両ルールは元々どのシナリオからも書き込まれる
#   マーカーファイルが存在せず、死んだルールになっていた
#   (レビューで判明した仕様の穴)。このスクリプトはそのマーカーファイル
#   2つに書き込むだけの最小限の操作を行なう。
#
#   docs/SPEC.md 5節は testbed_kill_marker (action: terminate,
#   scenarios/90-killme.sh が sensor-enforce.yml からのみ発火させる) しか
#   scenarios/*.sh との対応を明記していなかったが、同節のルール表には
#   testbed_detect_marker / testbed_collect_marker も定義されており、
#   これらを発火させるシナリオが存在しないと action: detect /
#   action: collect の実地検証ができない。sensor-monitor.yml
#   (monitor_mode: true) の全シナリオ実行の一部としてこのスクリプトを
#   呼ぶことで、90-killme.sh (sensor-enforce.yml, action: terminate) と
#   合わせて detect / collect / terminate の3アクションすべてが
#   実地検証できるようになる。
#
# 安全性:
#   行なうのはローカルの一時ファイルへの書き込みのみ。外部通信は行なわない。
#   実在の IOC は使わない。書き込むマーカーファイル名は
#   .cicd-sensor/rules/testbed.yaml の testbed_detect_marker /
#   testbed_collect_marker の条件 (path.endsWith("/cicd-sensor-*.marker"))
#   にのみ一致する、このテストベッド専用のファイル名。
#
# 期待される検知内容:
#   - cicd-sensor-detect.marker への書き込みで testbed_detect_marker
#     (action: detect) が発火する想定。
#   - cicd-sensor-collect.marker への書き込みで testbed_collect_marker
#     (action: collect) が発火する想定。
#   どちらも action: terminate ではないため、monitor_mode の値に関わらず
#   プロセスが kill されることはない (kill テストは 90-killme.sh /
#   sensor-enforce.yml が別途担当する)。
#
# docs/SPEC.md 4節の要件どおり: set -uo pipefail (set -e は使わない)、
# 終了コードは常に 0。

set -uo pipefail

SCENARIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCENARIO_DIR}/lib/common.sh"

load_canaries

step "write detect marker file (testbed_detect_marker, action: detect)"
detect_marker_path="${TESTBED_TMPDIR}/cicd-sensor-detect.marker"
echo "cicd-runtime-testbed detect-action trigger" > "${detect_marker_path}"
note "wrote ${detect_marker_path}; testbed_detect_marker rule should fire on this file_open(is_write) event"
end_step

step "write collect marker file (testbed_collect_marker, action: collect)"
collect_marker_path="${TESTBED_TMPDIR}/cicd-sensor-collect.marker"
echo "cicd-runtime-testbed collect-action trigger" > "${collect_marker_path}"
note "wrote ${collect_marker_path}; testbed_collect_marker rule should fire on this file_open(is_write) event"
end_step

exit 0
