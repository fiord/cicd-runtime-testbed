#!/usr/bin/env bash
#
# scenarios/04-persistence.sh
#
# 用途:
#   永続化 (persistence) の典型パターンのうち、比較的無害なものだけを
#   最小限に再現する: シェル起動スクリプトへの追記、および
#   .github/workflows/ 配下への (無効化された) ファイル作成。
#
# 安全性 (docs/SPEC.md 1節・4節を厳守):
#   - ~/.bashrc への追記はコメント行のみで、実行可能なコードは追加しない。
#   - .github/workflows/ に作るファイルは拡張子を `.yml.disabled` にし、
#     GitHub Actions が絶対にワークフローとして解釈しない名前にする
#     (有効なワークフローには絶対にしない)。
#   - ~/.ssh/authorized_keys への追記は行なわない
#     (実際の永続化に近すぎるため、意図的に省略している)。
#
# 期待される検知内容:
#   cicd-sensor / falco の `file_open` (is_write) ベースのルールが
#   ~/.bashrc や .github/workflows/ 配下への書き込みで発火する想定。
#
# docs/SPEC.md 4節の要件どおり: set -uo pipefail (set -e は使わない)、
# 終了コードは常に 0。

set -uo pipefail

SCENARIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCENARIO_DIR}/lib/common.sh"

load_canaries

step "append marker comment to ~/.bashrc"
printf '# cicd-runtime-testbed persistence scenario marker (04-persistence.sh)\n' >> "${HOME}/.bashrc"
note "appended a comment-only line to ~/.bashrc; no executable code added"
end_step

step "create disabled marker file under .github/workflows/"
workspace="${GITHUB_WORKSPACE:-$(pwd)}"
workflows_dir="${workspace}/.github/workflows"
mkdir -p "${workflows_dir}"
cat > "${workflows_dir}/_testbed_persistence.yml.disabled" <<'EOF'
# cicd-runtime-testbed scenario artifact (scenarios/04-persistence.sh).
#
# This file is intentionally NOT a valid, active GitHub Actions workflow.
# The `.yml.disabled` extension means GitHub Actions never parses or
# schedules it (only files ending in exactly `.yml` / `.yaml` under
# `.github/workflows/` are treated as workflows). It exists purely so a
# file_open(is_write) event under `.github/workflows/` can be observed as a
# persistence-style detection target.
name: disabled-testbed-persistence-marker
on: workflow_dispatch
EOF
note "created disabled marker file at ${workflows_dir}/_testbed_persistence.yml.disabled (never active)"
end_step

step "skip: ~/.ssh/authorized_keys is intentionally NOT touched"
note "docs/SPEC.md explicitly excludes authorized_keys persistence; nothing done here by design"
end_step

exit 0
