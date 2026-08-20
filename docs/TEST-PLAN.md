# TEST-PLAN

実行順序、カナリア表、シナリオ表、および各シナリオがどのツール・どのルールに
対応する想定かの対応表をまとめる。設計契約そのものは [`SPEC.md`](SPEC.md) を参照。

## 実行順序

```
1. sensor-monitor.yml   (monitor_mode: true, kill なし, 全シナリオ)
   falco-live.yml       (live mode, matrix, 全シナリオ)   ─ 1 と並行実行可
   falco-analyze.yml    (analyze mode, 全シナリオ)         ─ 1 と並行実行可
2. sensor-enforce.yml   (monitor_mode: false, 90-killme.sh のみ)
3. leak-scan.yml        (1 の run_id のいずれかを対象に T3 を確認。
                          2 (sensor-enforce.yml) の run_id は使えない —
                          90-killme.sh はカナリアを注入しないため)
```

1 のワークフローは互いに独立しているため並行実行して構わない。2 は
1 とは独立した検証 (kill 動作のみ) であり、どの順序でもよいが、
「まず検知が起きることを確認してから kill を確認する」順序を推奨する。
3 は 1 の run_id が出揃った後に実行する。**2 の run_id を 3 の入力に使わない
こと**（`leak-scan.yml` 側にガードがあり弾かれるが、そもそも意味がない）。

## カナリア表 (docs/SPEC.md §3 準拠)

| ID | 注入経路 | 期待結果 | 適用範囲 | 検証する仮説 |
| --- | --- | --- | --- | --- |
| `CANARY_ENV` | 環境変数 (GitHub Secrets 経由) | 漏れない | 両方 | GH のログ自動マスキングが効く／センサーは env を収集しない |
| `CANARY_FILE` | ファイル内容 (`~/.aws/credentials`) | 漏れない | 両方 | 両ツールともファイル内容は読まない (パスのみ記録) |
| `CANARY_PATH` | ファイルパス (`/tmp/CNRY.../marker`) | 漏れる | 両方 | cicd-sensor はパスを redact しない |
| `CANARY_ARGV_SHORT` | プロセス argv (12 バイト以下・キーワードなし) | 漏れる | 両方 | redaction ヒューリスティックのキーワード依存の穴 |
| `CANARY_ARGV_LONG` | プロセス argv (13 バイト以上・キーワードなし) | 漏れない (`<truncated, N bytes>`) | 両方 | 12 バイト超の切り詰めが効く |
| `CANARY_ARGV_FLAG` | プロセス argv (`Authorization: Bearer` ヘッダ) | 漏れない | 両方 | フラグ名ベースの redaction が効く |
| `CANARY_URL_QUERY` | 平文 HTTP のクエリ文字列 | 漏れない | 両方 | eBPF 内でクエリが除去される |
| `CANARY_URL_PATH` | 平文 HTTP のパス | 漏れる | 両方 | HTTP path は redact 対象外 |
| `CANARY_DNS` | DNS クエリのラベル (`*.test.invalid`) | 漏れる | 両方 | ドメイン名は redact 対象外 |
| `CANARY_SCAP` | 生の syscall バッファ | falco の `capture.scap` でのみ漏れる | **falco 固有** | snaplen 256 の生キャプチャに素通りで入る |

「適用範囲」が falco 固有のカナリアを cicd-sensor 単独の run (`sensor-monitor.yml`)
に対して走査すると、`tools/render-matrix.py` は ⚠️ ではなく N/A (対象外) と表示する
(docs/SPEC.md §7)。

## ランナー由来トークンの検出 (`tools/scan-leaks.sh` 二次走査)

カナリアとは別枠の検証項目。「capture.scap に GitHub 発行の本物のトークンが
実際に入るのか」を、パターン (実値ではない) で確認する。

| パターン | 検出対象 | 判定に使う exit code への影響 |
| --- | --- | --- |
| `github_token` | `ghs_` / `ghp_` / `gho_` / `ghu_` / `ghr_` に続く英数字列 | なし (`tools/render-matrix.py` の exit code はカナリアのみで決まる) |
| `jwt` | `eyJ` で始まる base64url セグメントがドット区切りで3つ連なった形 (`ACTIONS_RUNTIME_TOKEN` 等) | なし |

検出結果は `leak-report.json` の `runner_token_findings` (findings とは別の
トップレベルキー) に、パターン種別・ヒット件数・ファイル名のみで記録される
(実値は書かない)。既知のカナリア値に一致するものは除外する。
`tools/render-matrix.py` は job summary に「ランナー由来トークンのパターン検出」
という独立したセクションを出す。これは「発見」であって「失敗」ではないため、
⚠️ 判定や exit code には影響しない。

## シナリオ表と対応関係 (docs/SPEC.md §4 準拠)

| シナリオ | 主な操作 | falco-actions 側の想定対応 | cicd-sensor 側の想定対応 |
| --- | --- | --- | --- |
| `00-seed.sh` | 偽クレデンシャルの配置 (準備ステップ、検知対象ではない) | (該当なし、書き込みの副次的検知はありうる) | (該当なし) |
| `01-credential-access.sh` | `~/.aws/credentials` 等の cat、`/proc/self/environ` の読み取り、Runner トークンファイルの存在確認 | `Suspicious Process Reading GitHub Token`、`Process Reading Environment Variables of Others` (falco_cicd_rules.yaml) | baseline rules の generic-credential-access 系 |
| `02-exfil.sh` | DNS 解決失敗、平文 HTTP (クエリ/パス/Authorization ヘッダ)、HTTPS 対照群 | outbound connection 抽出 (analyze mode)、CI/CD ルールには専用の平文 HTTP ルールはない想定 | `domain` / `http_request` イベント種別のベースライン・カスタムルール |
| `03-npm-postinstall/` | npm postinstall からクレデンシュル読み取り + 外部通信 (最重要: プロセス系譜の検知能力比較) | 系譜4世代までを output に含めるが、ルール条件としては使っていない想定 → 汎用ルールでしか引っかからない | `process.ancestors` を使い npm の子孫であることを条件に含められる専用ルールで検知できる想定 |
| `04-persistence.sh` | `~/.bashrc` への追記、無効化された `.disabled` ワークフローファイルの作成 | `Possible Workflow File Overwrite` (`.github/workflows/` への書き込み) | file_open / file_move 系のベースライン・カスタムルール |
| `05-memfd-exec.sh` | `memfd_create` 経由の fileless 実行 | falco 側で memfd 相当の情報が取れるかを確認 (専用ルールがあるかは未確認) | `process_exec.is_memfd` |
| `06-anti-forensics.sh` | 00/05 が作った証跡の削除 | `File does not exist anymore` (SHA256 計算失敗) の確認 | `file_remove` |
| `07-rule-markers.sh` | detect / collect マーカーファイルへの書き込み (`sensor-monitor.yml` から実行。レビューで見つかった仕様の穴を塞ぐために追加) | (対象外、cicd-sensor 専用テスト) | `testbed_detect_marker` (action: detect) / `testbed_collect_marker` (action: collect) |
| `90-killme.sh` | kill 発火専用 (`sensor-enforce.yml` からのみ実行)。**`load_canaries` を呼ばずカナリアを注入しない** | (対象外、cicd-sensor 専用テスト) | `testbed_kill_marker` (action: terminate) |

## ワークフローとテレメトリの対応

| ワークフロー | 生成する telemetry アーティファクト | 検証目的 |
| --- | --- | --- |
| `falco-live.yml` | `telemetry-falco-live-0.39.0`, `telemetry-falco-live-0.39.2` | T1 (live 検知)、engine-version 不整合の実害確認 (falcosecurity/falco-no-driver の公開停止により `0.39.2` が事実上の上限。`0.43.0` は指定できない) |
| `falco-analyze.yml` | `telemetry-falco-analyze` | T1 (analyze 検知)、T2 (抽出情報の網羅確認) |
| `sensor-monitor.yml` | `telemetry-cicd-sensor-monitor` | T1 (検知、kill なし)、T2 |
| `sensor-enforce.yml` | `telemetry-cicd-sensor-enforce` (+ `assert` ジョブの成否が T1 の kill 判定そのもの) | T1 (kill)。**カナリアを注入しないため T3 (leak-scan.yml) の対象にはできない** |
| `leak-scan.yml` | `leak-report-<run_id>` | T3 (`falco-live.yml` / `falco-analyze.yml` / `sensor-monitor.yml` いずれかの telemetry を横断走査。`sensor-enforce.yml` は対象外) |

## 前提条件

- `CANARY_ENV` シークレットが登録されていること (未登録でも動くが、その項目の検証意義が失われる。README 参照)
- falco-actions の SHA が `PIN_ME_SEE_README` から実際のコミット SHA に置換されていること (README 参照)
- `cicd-sensorctl` の入手経路 (README 参照) が実際に機能することを事前に確認していること (未検証の推定のため)
