#!/usr/bin/env bash
#
# scenarios/01-credential-access.sh
#
# 用途:
#   00-seed.sh が配置した偽クレデンシャルを読み取る。プロセスによる
#   クレデンシャルファイルアクセスの検知能力を確認するための最小コマンド列。
#
# 安全性:
#   すべて 00-seed.sh が用意した偽 (CNRY-...) の値が入ったファイルのみを
#   対象とする。/proc/self/environ は自プロセスのみを読む
#   (他プロセスの environ は読まない)。GitHub Actions のランタイム
#   トークンファイルは存在確認 (ls) のみで、中身は一切読まない。
#   出力はすべて破棄し、ログに値そのものを残さない。
#
# 期待される検知内容:
#   falco の "Suspicious Process Reading GitHub Token" 系、および
#   cicd-sensor の generic-credential-access.yaml 系ルール
#   (aws_credential_read, docker_credential_read など) が発火する想定。
#
# docs/SPEC.md 4節の要件どおり: set -uo pipefail (set -e は使わない)、
# 終了コードは常に 0。

set -uo pipefail

SCENARIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCENARIO_DIR}/lib/common.sh"

load_canaries

step "read fake AWS credentials"
safe_run bash -c 'cat "${HOME}/.aws/credentials" >/dev/null'
end_step

step "read fake Docker config"
safe_run bash -c 'cat "${HOME}/.docker/config.json" >/dev/null'
end_step

step "read fake npm registry token"
safe_run bash -c 'cat "${HOME}/.npmrc" >/dev/null'
end_step

step "read own process environ (/proc/self/environ)"
# 他プロセスの environ は読まない。自プロセスのみ。
safe_run bash -c 'cat /proc/self/environ >/dev/null'
end_step

step "check existence of GitHub Actions runtime token file(s) under RUNNER_TEMP"
if [ -n "${RUNNER_TEMP:-}" ] && [ -d "${RUNNER_TEMP}" ]; then
  # 中身は読まない。存在確認 (ls) のみ。
  safe_run ls -la "${RUNNER_TEMP}"
else
  note "RUNNER_TEMP not set or not a directory; skipping runtime token file existence check"
fi
end_step

exit 0
