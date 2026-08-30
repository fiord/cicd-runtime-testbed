# TEST-PLAN

実行順序、カナリア表、シナリオ表、および各シナリオがどのツール・どのルールに
対応する想定かの対応表をまとめる。設計契約そのものは [`SPEC.md`](SPEC.md) を参照。

## 実行順序

```
1. sensor-monitor.yml   (monitor_mode: false [コミット値、全ワークフロー共通。SPEC.md §5参照],
                          自作ルールでの kill なし, 全シナリオ)
   falco-live.yml       (live mode, matrix, 全シナリオ)   ─ 1 と並行実行可
   falco-analyze.yml    (analyze mode, 全シナリオ)         ─ 1 と並行実行可
2. sensor-enforce.yml   (monitor_mode: false [同上], 90-killme.sh のみ)
3. leak-scan.yml        (1 の run_id のいずれかを対象に T3 を確認。
                          2 (sensor-enforce.yml) の run_id は使えない —
                          90-killme.sh はカナリアを注入しないため)
```

**3 は既定では自動で走る** (docs/REQUIRED-FIXES.md R-10)。`leak-scan.yml`
は 1 の 3 ワークフローの完了を `workflow_run` で拾い、その run を対象に
自動起動する。手で `run_id` を渡す `workflow_dispatch` は、過去の run を
測り直したいときのために残してある。

> ⚠️ `workflow_run` トリガはデフォルトブランチ上のワークフロー定義でしか
> 発火しない。ブランチで検証している間は手動起動を使うこと。

`monitor_mode` は `.cicd-sensor/config.yaml` のコミット値で決まり、
`cicd-sensor-action` がコミット SHA から設定を取得する仕様上
（`docs/SPEC.md` §5）、ワークフローごとに切り替えることはできない。
`sensor-monitor.yml` でも `monitor_mode: false` が使われるが、自作ルールで
`action: terminate` を持つ `testbed_kill_marker` は `sensor-enforce.yml`
専用の `90-killme.sh` でしか発火しないため、通常はこのワークフローで
kill は起きない（ベースラインの terminate ルールに触れた場合を除く。
詳細は `docs/SPEC.md` §5 / `docs/INVESTIGATION.md` を参照）。

1 のワークフローは互いに独立しているため並行実行して構わない。2 は
1 とは独立した検証 (kill 動作のみ) であり、どの順序でもよいが、
「まず検知が起きることを確認してから kill を確認する」順序を推奨する。
3 は 1 の run_id が出揃った後に実行する。**2 の run_id を 3 の入力に使わない
こと**（`leak-scan.yml` 側にガードがあり弾かれるが、そもそも意味がない）。

## カナリア表 (docs/SPEC.md §3 準拠)

| ID | 注入経路 | 期待結果 | 適用範囲 | 採点対象 | 観測に必要な証跡粒度 | 検証する仮説 |
| --- | --- | --- | --- | --- | --- | --- |
| `CANARY_ENV` | 環境変数 (GitHub Secrets 経由) | 漏れない | 両方 | 両方 scored | 集計でも判定対象 | GH のログ自動マスキングが効く／センサーは env を収集しない |
| `CANARY_FILE` | ファイル内容 (`~/.aws/credentials`) | 漏れない | 両方 | 両方 scored | 詳細以上 | 両ツールともファイル内容は読まない (パスのみ記録) |
| `CANARY_PATH` | ファイルパス (`/tmp/CNRY.../marker`) | 漏れる | 両方 | cicd-sensor: scored／falco: informational | 詳細以上 | cicd-sensor はパスを redact しない |
| `CANARY_ARGV_SHORT` | プロセス argv (`02-exfil.sh` の `curl --referer "${CANARY_ARGV_SHORT}"`。独立した argv 要素、12 バイト以下・キーワードなし) | 漏れる | 両方 | cicd-sensor: scored／falco: informational | 詳細以上 | redaction ヒューリスティックのキーワード依存の穴 |
| `CANARY_ARGV_LONG` | プロセス argv (`02-exfil.sh` の `curl -A "${CANARY_ARGV_LONG}"`。独立した argv 要素、13 バイト以上・キーワードなし) | 漏れない (`<truncated, N bytes>`) | 両方 | cicd-sensor: scored／falco: informational | 詳細以上 | 12 バイト超の切り詰めが効く |
| `CANARY_ARGV_FLAG` | プロセス argv (`Authorization: Bearer` ヘッダ) | 漏れない | 両方 | cicd-sensor: scored／falco: informational | 詳細以上 | フラグ名ベースの redaction が効く |
| `CANARY_URL_QUERY` | 平文 HTTP のクエリ文字列 | 漏れない | 両方 | cicd-sensor: scored／falco: informational | 詳細以上 | eBPF 内でクエリが除去される |
| `CANARY_URL_PATH` | 平文 HTTP のパス | 漏れる | 両方 | cicd-sensor: scored／falco: informational | 詳細以上 | HTTP path は redact 対象外 |
| `CANARY_DNS` | DNS クエリのラベル (`*.test.invalid`) | 漏れる | 両方 | cicd-sensor: scored／falco: informational | 集計でも判定対象 (`domains` 配列に host 単位で載る) | ドメイン名は redact 対象外 |
| `CANARY_SCAP` | 生の syscall バッファ | falco の `capture.scap` でのみ漏れる | **falco 固有** | falco: scored (raw 粒度必須) | 生 (capture.scap そのもの) | snaplen 256 の生キャプチャに素通りで入る |

「適用範囲」が falco 固有のカナリアを cicd-sensor 単独の run (`sensor-monitor.yml`)
に対して走査すると、`tools/render-matrix.py` は ⚠️ ではなく N/A (対象外) と表示する
(docs/SPEC.md §7)。

「採点対象」は「適用範囲」とは別の軸で、「そのツールに対して採点可能な仮説を
持っているか」を表す (docs/SPEC.md §7「採点対象 (scored)／参考情報 (informational)
の区別」)。`CANARY_ENV` / `CANARY_FILE` 以外の8個は元々「cicd-sensor の redaction
挙動の検証」を目的に設計されており、redaction 層を持たない falco にはそもそも
採点可能な仮説が無い。実地実行 (run 32643269616。falco-live の run 32625231129 に
対する leak-scan) で、これらのカナリアを falco に対して cicd-sensor 用の期待値で
採点してしまい、`CANARY_PATH` / `CANARY_ARGV_SHORT` / `CANARY_DNS` / `CANARY_SCAP`
の4件が⚠️になる問題が見つかったことへの対応。falco に対しては informational
(検出の有無は表示するが ✅/⚠️ を付けず、exit code にも算入しない) として扱う。
`CANARY_SCAP` は falco に対して scored のままだが、`capture.scap` (raw 粒度) が
無い場合は証跡粒度 N/A になる (以前はこの粒度チェックの対象外で、`capture.scap`
の無い falco live モードに対して誤って ⚠️ になっていた)。

「観測に必要な証跡粒度」が「詳細以上」のカナリアは、cicd-sensor の standalone モードで
得られる attestation predicate (集計のみ。個別イベントの timestamp / argv /
プロセスツリー、ファイルアクセスのパス、`collect` アクションのヒット、HTTP の
path/host を含まない) しか走査対象に無い場合、⚠️ ではなく **N/A (この証跡粒度では
観測不能)** と表示される。実地実行 (run 32381640678, sensor-monitor.yml) では、
アーティファクトが `cicd-sensor-attestation/predicate.json` 1 ファイルのみだったため、
`CANARY_DNS` (集計でも判定対象) 以外の「漏れる」はずのカナリアはすべてこの N/A に
分類され、「乖離なし」と正しく判定された (docs/SPEC.md §3, §6, §7)。

## 前提: cicd-sensor はルールに一致したイベントの詳細しか記録しない (run 32510077347)

HTML レポート (詳細レベルの証跡) であっても、cicd-sensor は「ルールに一致した
イベント」の `hits[]` にしか `process.argv` / `payload` の詳細を記録しない。
ルールに一致しないイベントは standalone モードのレポートに一切現れない
(`domain_observations[]` / `network_connections[]` はルール一致に関係なく
載る例外だが、`argv` を持たない)。このため `CANARY_ARGV_SHORT` /
`CANARY_ARGV_LONG` / `CANARY_PATH` / `CANARY_URL_PATH` は、それらを運ぶ
プロセス・イベントが `.cicd-sensor/rules/testbed.yaml` の何らかのルールに
一致しない限り、原理的に観測できない。この対応として
`cicd_runtime_testbed/canary_observability` ruleset
(`testbed_canary_argv_carrier` / `testbed_canary_path_probe` /
`testbed_canary_http_host`、すべて `action: collect`) を追加した
(docs/SPEC.md §5)。

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
| `00-seed.sh` | 偽クレデンシャルの配置 (準備ステップ、検知対象ではない)。`/tmp/${CANARY_PATH}/canary-path-probe.marker` も作る | (該当なし、書き込みの副次的検知はありうる) | `testbed_canary_path_probe` (action: collect) |
| `01-credential-access.sh` | `~/.aws/credentials` 等の cat、`/proc/self/environ` の読み取り、Runner トークンファイルの存在確認 | `Suspicious Process Reading GitHub Token`、`Process Reading Environment Variables of Others` (falco_cicd_rules.yaml) | baseline rules の generic-credential-access 系 |
| `02-exfil.sh` | DNS 解決失敗、平文 HTTP (クエリ/パス/Authorization ヘッダ/argv カナリア)、HTTPS 対照群 | outbound connection 抽出 (analyze mode)、CI/CD ルールには専用の平文 HTTP ルールはない想定 | `domain` / `http_request` イベント種別のベースライン・カスタムルール、`testbed_canary_argv_carrier` (curl 実行全般、action: collect)、`testbed_canary_http_host` (host==example.com、action: collect) |
| `03-npm-postinstall/` | npm postinstall からクレデンシュル読み取り + 外部通信 (最重要: プロセス系譜の検知能力比較) | 系譜4世代までを output に含めるが、ルール条件としては使っていない想定 → 汎用ルールでしか引っかからない | `process.ancestors` を使い npm の子孫であることを条件に含められる専用ルールで検知できる想定 |
| `04-persistence.sh` | `~/.bashrc` への追記、無効化された `.disabled` ワークフローファイルの作成 | `Possible Workflow File Overwrite` (`.github/workflows/` への書き込み) | file_open / file_move 系のベースライン・カスタムルール |
| `05-memfd-exec.sh` | `memfd_create` 経由の fileless 実行 | **実測で未検知**。falco 標準ルールセットには `Fileless execution via memfd_create` (CRITICAL) が有効な状態で含まれるため、標準ルールがロードされていれば鳴るはず → R-4 の `STD_RULES` 観測で確定させる | **実測で未検知**。観測プローブ `testbed_probe_memfd_exec` (`event_type: process_exec` / `condition: is_memfd`、action: collect) で「見えていないのか、ルールが無いだけか」を切り分ける |
| `06-anti-forensics.sh` | 00/05 が作った証跡の削除 | **実測で未検知**。`File does not exist anymore` (SHA256 計算失敗) の確認のみ | **実測で未検知**。観測プローブ `testbed_probe_evidence_removal` (`event_type: file_remove` / `condition: path.endsWith("/05-memfd-driver.py")`、action: collect) で同上の切り分けを行う |
| `07-rule-markers.sh` | detect / collect マーカーファイルへの書き込み (`sensor-monitor.yml` から実行。レビューで見つかった仕様の穴を塞ぐために追加) | (対象外、cicd-sensor 専用テスト) | `testbed_detect_marker` (action: detect) / `testbed_collect_marker` (action: collect) |
| `90-killme.sh` | kill 発火専用 (`sensor-enforce.yml` からのみ実行)。**`load_canaries` を呼ばずカナリアを注入しない** | (対象外、cicd-sensor 専用テスト) | `testbed_kill_marker` (action: terminate) |

## テレメトリ収集の完全性 (`telemetry-manifest.txt`)

`sensor-monitor.yml` / `sensor-enforce.yml` の collect-telemetry ジョブと
`falco-analyze.yml` の analyze ジョブは、期待するアーティファクト／抽出ファイルの
うちどれが実際に取得できたかを `telemetry-manifest.txt` (各 telemetry アーティファクトに
同梱) と job summary に記録する。1 つも取得できなければジョブは失敗し、一部だけの場合は
`::warning::` を出して続行する (docs/SPEC.md §6)。`tools/scan-leaks.sh` は
`telemetry-manifest.txt` をカナリア走査から除外しない。

## `telemetry_dirs` とツール種別判定の不整合の修正

`leak-report.json` に `telemetry_dirs` (`scan_root` 直下のディレクトリ名一覧、
`tools/scan-leaks.sh` が走査時点で記録する) を追加した。`tools/render-matrix.py`
のツール種別判定 (present_tools) はこれを優先して使う。以前はこの判定に
実行時の `os.listdir(scan_root)` を直接使っており、`render-matrix.py` を
走査時と異なる環境・カレントディレクトリで実行すると (例: `leak-report.json`
だけを後から読む場合)、証跡粒度判定 (`detect_evidence_granularity`、
scan_root 配下を再帰的に歩くため名前の一致に依存しない) は正しく機能するのに
ツール種別判定だけが「判定不能」になる、という不整合が起きていた。

さらに、ツール種別が判定不能な場合のフォールバックも見直した。以前は
「安全側に倒して全カナリアを判定対象にする」だったが、これは falco 固有の
`CANARY_SCAP` に対しては cicd-sensor 単独の run を走査するたびに必ず
⚠️ (exit 1) を生む誤検知だった。修正後は、ツール固有のカナリア
(`CANARY_SCAP`) のみ判定不能時に N/A とし、両ツール共通のカナリアは
従来どおり判定する (docs/SPEC.md §7)。

## カナリア走査の大文字小文字非依存化

`tools/scan-leaks.sh` のカナリア本走査 (`findings`) は大文字小文字を区別しない。
DNS 名はリゾルバによって小文字に正規化されるため、以前の大文字小文字を区別する実装では
`CANARY_DNS` の漏洩を見逃す偽陰性が実地実行 (run 32381640678) で発生していた。
`runner_token_findings` (ランナー由来トークンの二次走査) は対象外で、引き続き
大文字小文字を区別する (docs/SPEC.md §7)。

## カナリアの採点対象 (scored) ／ 参考情報 (informational) の区別

実地実行 (run 32643269616。falco-live-forked の run 32625231129 を対象にした
leak-scan) で、`CANARY_PATH` / `CANARY_ARGV_SHORT` / `CANARY_DNS` / `CANARY_SCAP`
の4件が falco の run に対して ⚠️ (乖離) と判定されて失敗する問題が見つかった。
対象テレメトリを実際に展開して確認したところ、`capture.scap` は含まれず (live
モードは生キャプチャを作らない)、検知イベントは 80 件すべて `Source Code
Overwrite` だった。この4件はすべて構造的に成立しえないもので、真の発見では
なかった。

原因は、これらのカナリアが本来「cicd-sensor の redaction 挙動を検証するために
設計されたもの」であるにもかかわらず、redaction 層を持たない falco にも同じ
期待値を適用して採点していたことにある。falco の出力はルールの `output:`
テンプレートに書かれた内容がそのまま出るだけなので、「カナリアが現れるか」は
cicd-sensor の redaction 挙動とは無関係に決まる、まったく別の問いである。

この対応として `tools/render-matrix.py` に「採点対象 (scored)」と「参考情報
(informational)」の区別を導入した (上記カナリア表の「採点対象」列、
docs/SPEC.md §7 参照)。合わせて `CANARY_SCAP` の証跡粒度要求を「詳細以上」から
「生 (`capture.scap` そのもの)」に修正した (以前はこのチェックの対象外だった
ため、`capture.scap` の無い falco live モードに対して誤って ⚠️ になっていた)。
既存の3つの N/A 機構 (ツール種別 / 証跡粒度 / `http_request` サポート) は
維持したまま、この scored/informational の区別とは独立に動く。

## 公平性: ハーネス自身のノイズの除去 (R-3)

**問題 (実測)**: fork leg (falco 0.44.1) が出したアラート 240 件のうち
**213 件 (89%)** は、シナリオが起こした事象ではなく
`scenarios/lib/common.sh` が `${RUNNER_TEMP}/cicd-runtime-testbed-log.jsonl`
に実行ログを追記したことに対する `"Source Code Overwrite"` だった。
falco の CI/CD ルールは

```
open_write and fd.directory startswith "/home/runner/work/"
```

で発火し、その例外は `proc.exepath` が `Runner.Worker` の場合だけである。
ハーネスは bash から書くのでこの例外に当たらない。つまり **テスト装置
自身が測定対象を汚染していた**。

**採った対応**: どちらかのツールに除外ルールを足すのではなく、
**ハーネス側をワークスペース外に退避させた**。
`scenarios/lib/common.sh` の既定値を次のように変更した。

| 変数 | 変更前 | 変更後 |
| --- | --- | --- |
| `TESTBED_TMPDIR` | `${RUNNER_TEMP:-/tmp}/cicd-runtime-testbed` | `/var/tmp/cicd-runtime-testbed` |
| `TESTBED_LOG` | `${RUNNER_TEMP:-/tmp}/cicd-runtime-testbed-log.jsonl` | `${TESTBED_TMPDIR}/testbed-log.jsonl` |

**なぜこれが公平か**: この変更はどちらのツールの設定にも触れていない。

- **falco**: ルールファイルは一切変更していない。出荷時の
  `falco_cicd_rules.yaml` がそのまま適用される。単に、ハーネスが
  監視対象ディレクトリに書き込むのをやめただけである。
- **cicd-sensor**: `.cicd-sensor/rules/testbed.yaml` のルールは
  `path.endsWith("<basename>")` で照合しており、ディレクトリ位置に
  依存しない。よって発火条件は変更前後で同一である。ベースラインルール
  についても、対象は `~/.aws/credentials` などの絶対パスであり
  `$RUNNER_TEMP` には依存しない。

「同じ除外を両ツールに適用する」という代替案 (falco に
`/home/runner/work/_temp/cicd-runtime-testbed*` の除外ルールを渡す) は
採らなかった。falco 側だけ出荷時と異なるルールセットで測ることになり、
かつ cicd-sensor 側には対応する「除外」が存在しない (そもそも発火して
いない) ため、非対称になるからである。

**この変更の副作用 (結論に影響するので明記)**:
`scenarios/05-memfd-exec.sh` がドライバ `.py` を `$TESTBED_TMPDIR` に
書くため、falco はこれを `"Source Code Overwrite"` として検知していた。
変更後、falco は **05 を一切検知しなくなる**。これは検知能力が落ちた
のではなく、**もともと 05 の本質 (memfd 経由の fileless 実行) を
検知していたわけではなく、ドライバスクリプトの作成という副作用を
偶然拾っていただけ**であることが可視化されたということである。
結果表では 05 を「両ツールとも未検知」として扱う (R-11 参照)。

## 公平性: ルールセットの母数が違うため検知件数は直接比較できない (R-4)

**測定された非対称性**:

| | falco (`falco_cicd_rules.yaml`) | cicd-sensor (ベースライン + testbed) |
| --- | --- | --- |
| CI/CD 向けルール数 | 6 | `rule_count=64` |
| 実測で発火した種類数 | 1 (`"Source Code Overwrite"`) | 9 |

**この 1 対 9 を「検知能力の差」として提示してはならない。**
母数が 6 対 64 である以上、これは大部分がルールセットの規模の差である。

**採らなかった選択肢**: cicd-sensor の 64 本のベースラインルールに
対応する falco ルールを手書きして渡す、という案は採用しなかった。
それは「両ツールで何が出荷されているか」ではなく「我々が何を書けるか」
を測ることになり、この testbed の目的 (docs/SPEC.md §1: 出荷時構成での
比較) から外れる。書き手が falco 側のルールを書く以上、cicd-sensor の
ルールを写経した falco ルールが cicd-sensor と同じものを検知するのは
当然で、比較として無意味である。

**採った対応**:

1. `falco-live.yml` の観測用アサート
   (`Assert (observational): CI/CD rules loaded?`) を拡張し、
   **falco 標準ルールセット (`/etc/falco/falco_rules.yaml`) が実際に
   ロードされているか**も記録する。falco の既定 `falco.yaml` の
   `rules_files:` は `/etc/falco/falco_rules.yaml` /
   `falco_rules.local.yaml` / `rules.d` を含むため、live モードでも
   標準ルールはロードされている**はず**である
   (R-4 本文の「live では cicd_rules.yaml しかロードしていない」という
   記述はこの点で疑わしい)。これを推測ではなく実測で確定させる。
   これは falco の構成を変える変更ではなく、**何がロードされたかを
   記録するだけ**の観測ステップである。
2. 結果の提示単位を「アラート件数」ではなく
   **「シナリオごとに、出荷時構成でそのツールが何か気づいたか (Yes/No)」**
   にする。件数は参考値として併記するに留める。

**結論に明記すること**: 「falco 1 種類 vs cicd-sensor 9 種類」という
数字は、**そのまま比較できない**。比較できるのは
「01-credential-access を falco の出荷時 CI/CD ルールは検知しないが
cicd-sensor の出荷時ルールは検知する」といった、シナリオ単位の
Yes/No である。これは製品の設計思想の差 (falco の CI/CD ルールは
「ソースコード改変」「パッケージマネージャからの実行」といった
CI 固有の少数の観点に絞っており、認証情報アクセスの網羅的な検知は
対象にしていない) を反映しており、それ自体が結論として意味を持つ。

## どちらのツールも検知していない 2 シナリオの扱い (R-11)

**05-memfd-exec** と **06-anti-forensics** は、実測で
**falco / cicd-sensor のどちらからも検知されなかった**。

**方針: 2 シナリオとも残す。ただし検知件数の比較からは除外し、
結果表には「両ツールの出荷時ルールセットでは未検知」と明示する。**
黙って落とすと「測ったが出なかった」が「測っていない」と区別できなくなる。

**「未検知」の 2 つの意味を切り分ける**:

| | 意味 | 評価上の扱い |
| --- | --- | --- |
| (a) | センサーがそのイベントを**観測できていない** | センサーの可視性の限界。ツールの能力差として意味がある |
| (b) | 観測はできているが**出荷時ルールセットに該当ルールが無い** | ルールセットの網羅範囲の問題。設計思想の差として意味がある |

(a) と (b) を混同したまま「未カバー」と書くのは不誠実なので、
両ツールにそれぞれ切り分けの手段を用意した。

**cicd-sensor 側**: `.cicd-sensor/rules/testbed.yaml` に ruleset
`cicd_runtime_testbed/uncovered_scenarios` を追加し、`action: collect`
の観測プローブを 2 本置いた (`testbed_probe_memfd_exec` /
`testbed_probe_evidence_removal`)。ヒットすれば (b)、
ヒットしなければ (a)。どちらも `collect` なのでジョブは止めない。

**falco 側**: 対称な観測を**独自ルールでは書かない**。R-4 と同じ理由で、
手書きルールを足すと「出荷時に何が鳴るか」ではなく「我々が何を書けるか」
の測定になる。falco の標準ルールセットには
**`Fileless execution via memfd_create` (priority CRITICAL) が有効な状態で
最初から含まれている**ため、falco 側の問いは
「標準ルールセットがロードされているか」に還元でき、R-4 で追加した
`falco-live.yml` の observational assert (`STD_RULES`) がそのまま答えになる。
`STD_RULES=yes` なのに 05 が鳴っていないなら、それは
「標準ルールがロードされているのに fileless exec を捉えられていない」
という、それ自体が report する価値のある事実である。

**⚠️ 両ツールで完全に同じ問いにはなっていない**。
cicd-sensor 側は「イベントが見えるか」を直接プローブしているのに対し、
falco 側は「該当ルールがロードされているか」を見ているだけで、
イベントが見えているかどうかは間接的にしか分からない。
これは公平性の欠陥ではなく**出荷時構成の非対称性そのもの**である
(falco は標準ルールセットに memfd ルールを持ち、cicd-sensor は持たない)。
結果を書くときはこの非対称性を明示すること。

**R-3 の副作用との関係**: `$TESTBED_TMPDIR` をワークスペース外へ移した
結果、falco は 05 でドライバ `.py` の作成すら検知しなくなる。
これは検知能力の低下ではなく、もともと 05 の本質 (memfd 経由の
fileless 実行) を捉えていたわけではなく**ハーネスのファイル書き込みを
拾っていただけ**だったことが可視化されたにすぎない (R-3 の節を参照)。

**シナリオが弱すぎるのではないか、という疑い**: 弱くはないと判断した。
05 は `os.memfd_create` + `os.set_inheritable` + `execv("/proc/self/fd/N")`
という fileless 実行の教科書どおりの形であり、falco の標準ルールが
名指しで狙っている挙動そのものである。検知されないのはシナリオの
問題ではなく構成の問題である可能性が高い。

## ワークフローとテレメトリの対応

| ワークフロー | 生成する telemetry アーティファクト | 検証目的 |
| --- | --- | --- |
| `falco-live.yml` | `telemetry-falco-live-0.39.0`, `telemetry-falco-live-0.39.2`, `telemetry-falco-live-forked-0.44.1` | T1 (live 検知)、upstream/fork 比較。upstream は `0.39.2` が上限で、fork は `0.44.1` を使う。job の緑だけで検知成功と判定しない |
| `falco-analyze.yml` | `telemetry-falco-analyze` | T1 (analyze 検知)、T2 (抽出情報の網羅確認) |
| `sensor-monitor.yml` | `telemetry-cicd-sensor-monitor` | T1 (検知、kill なし)、T2 |
| `sensor-enforce.yml` | `telemetry-cicd-sensor-enforce` (+ `assert` ジョブの成否が T1 の kill 判定そのもの) | T1 (kill)。**カナリアを注入しないため T3 (leak-scan.yml) の対象にはできない** |
| `leak-scan.yml` | `leak-report-<run_id>` | T3 (`falco-live.yml` / `falco-analyze.yml` / `sensor-monitor.yml` いずれかの telemetry を横断走査。`sensor-enforce.yml` は対象外)。**3 ワークフローの完了で `workflow_run` により自動起動する** (R-10) |

## 前提条件

- `CANARY_ENV` シークレットが登録されていること (未登録でも動くが、その項目の検証意義が失われる。`docs/SETUP.md` 参照)
- upstream falco-actions が commit `558a3ceeee9403e1c875ffbeb704c34c93e24752` に pin されていること。fork leg の branch 参照は意図的な一時例外である (`docs/SETUP.md` 参照)
- `cicd-sensorctl` の入手経路は実機確認済み。
  リリースタグが `releases/<version>` 形式である点に注意 (docs/REQUIRED-FIXES.md R-1)
- 各ワークフローの `env: CICD_SENSOR_VERSION` が v0.0.46 以上であること。
  下げる場合は `.cicd-sensor/rules/testbed.yaml` の `testbed_canary_http_host`
  も同時に無効化しないと、プロジェクト設定全体が agent に届かなくなる
  (docs/REQUIRED-FIXES.md R-2)
