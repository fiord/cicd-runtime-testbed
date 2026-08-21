#!/usr/bin/env bash
#
# scenarios/00-seed.sh
#
# 用途:
#   後続シナリオ (01, 05, 06 など) が読み書きする「偽クレデンシャル」を
#   配置する。CANARY_FILE / CANARY_PATH を実ファイルに埋め込み、
#   01-credential-access.sh がそれを読む対象を作る。また、
#   .cicd-sensor/rules/testbed.yaml の観測用ルール
#   (testbed_canary_path_probe) を発火させる専用マーカーファイルも
#   ここで作成する (cicd-sensor はルールに一致したイベントの詳細しか
#   記録しないため。docs/SPEC.md 5節参照)。
#
# 安全性:
#   ここで書き込む値はすべて canaries/canaries.env 由来の偽値 (CNRY-...)。
#   実在の AWS / Docker / npm の認証情報は一切使わない。書き込み先は
#   $HOME 配下と $TMPDIR 配下のみで、外部通信は行わない。
#
# 期待される検知内容:
#   このスクリプト自体はファイル書き込みのみを行なう「準備」ステップ。
#   cicd-sensor / falco がクレデンシャル格納パスへの書き込みを記録する
#   場合はここで発火し得るが、本来の検知対象は 01 (読み取り) 側。
#
# docs/SPEC.md 4節の要件どおり: set -uo pipefail (set -e は使わない)、
# 終了コードは常に 0。

set -uo pipefail

SCENARIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCENARIO_DIR}/lib/common.sh"

load_canaries

step "seed: fake AWS credentials (~/.aws/credentials)"
mkdir -p "${HOME}/.aws"
cat > "${HOME}/.aws/credentials" <<EOF
[default]
aws_access_key_id = CNRY-FAKE-ACCESS-ID-DONOTUSE
aws_secret_access_key = ${CANARY_FILE}
EOF
note "wrote fake ~/.aws/credentials containing CANARY_FILE (content, not path)"
end_step

step "seed: fake Docker config (~/.docker/config.json)"
mkdir -p "${HOME}/.docker"
cat > "${HOME}/.docker/config.json" <<'EOF'
{
  "auths": {
    "registry.example.com": {
      "auth": "cnry-fake-docker-auth-donotuse"
    }
  }
}
EOF
note "wrote fake ~/.docker/config.json"
end_step

step "seed: canary path marker (/tmp/\${CANARY_PATH}/marker)"
marker_dir="/tmp/${CANARY_PATH}"
mkdir -p "${marker_dir}"
printf 'cicd-runtime-testbed marker file\n' > "${marker_dir}/marker"
note "created marker directory whose name is CANARY_PATH itself"
end_step

step "seed: canary path observation marker (/tmp/\${CANARY_PATH}/canary-path-probe.marker)"
# .cicd-sensor/rules/testbed.yaml の testbed_canary_path_probe ルール
# (event_type: file_open, action: collect) がこのファイル名一致で発火する。
# cicd-sensor はルールに一致したイベントの詳細しか記録しない (「実地実行で
# 判明した最重要の事実」。README / docs/SPEC.md 5節参照) ため、CANARY_PATH
# を含むディレクトリへの書き込みが発火対象にならない限り payload.path は
# 一切レポートに現れない。上の "marker" とは別に、この専用ファイル名
# (canary-path-probe.marker) にだけ一致する観測用ルールを用意することで、
# ディレクトリ名 (=CANARY_PATH の値) を含む path がヒットの payload に
# 確実に記録されるようにする。
printf 'cicd-runtime-testbed canary-path observation probe\n' > "${marker_dir}/canary-path-probe.marker"
note "created canary-path-probe.marker to trigger testbed_canary_path_probe (collect)"
end_step

step "seed: fake npm registry token (~/.npmrc)"
printf '//registry.npmjs.org/:_authToken=CNRY-FAKE-NPM-TOKEN-DONOTUSE\n' >> "${HOME}/.npmrc"
note "appended fake registry token line to ~/.npmrc"
end_step

exit 0
