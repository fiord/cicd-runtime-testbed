# RESULTS

実行結果を記入するためのテンプレート。ワークフローを実行するたびに、このファイルを
コピーして (例: `work_docs/results-2026-08-19.md` のようなローカル作業用の場所に、
このリポジトリの `docs/` 配下ではなく) 埋めていくことを想定している。

- 実行日:
- 実行者:
- 対象コミット (SHA):
- 使用した falco-actions の SHA (README 手順で確定したもの):
- `cicd-sensorctl` 入手経路の検証結果 (成功 / 失敗、失敗時の対処):

---

## 調査結果: falco-actions が使えるイメージバージョンの上限 (falco-no-driver 公開停止)

これはバグではなく、falco-actions に関する重要な調査結果である。以下を必ず記入すること。

- **確認事実**: falco-actions の `start` / `analyze` action は使用イメージを
  `IMAGE="falcosecurity/falco-no-driver"` にハードコードしている
  (`falco-actions/start/action.yaml`, `analyze/action.yaml`)。このイメージは
  Docker Hub 上の数値バージョンタグの最大が `0.39.2` で止まっている
  (`latest` の最終 push も 2024-11-21 で、事実上メンテナンスが止まっている)。
  falco 本体イメージ (`falcosecurity/falco`) は `0.44.1` まであり `latest` の
  push も新しいが、falco-actions はそちらを使わないため、このテストベッドから
  利用する手段はない。**したがって falco-actions が使える Falco のバージョンは
  実質 `0.39.2` が上限である。**
- 一方、falco-actions 同梱の CI/CD ルール (`rules/falco_cicd_rules.yaml`) は
  先頭で `required_engine_version: 0.43.0` を要求している。
- **仮説**: 上記2点から、「falco-actions は、自身の同梱 CI/CD ルールが
  要求するエンジンバージョンを満たすイメージを pull できない可能性が高い」
  という仮説が立つ。
- **今回の実行で得られた実測 (ここが T1 の中核的な観測結果)**:
  - `falco-live.yml` (`falco-version: 0.39.0` および `0.39.2`) で、
    `required_engine_version: 0.43.0` のルールを実際にロードできたか /
    拒否されたか / 警告のみで通ったか (job summary の
    "required_engine_version" セクション、`falco_start_logs.txt` を参照):
    - `0.39.0`:
    - `0.39.2`:
  - `falco-analyze.yml` (`falco-version: 0.39.2`) で、同じルールファイルを
    `custom-rule-file` として明示的に渡した場合の結果 (`Analyze capture`
    ステップの outcome、job summary の "required_engine_version" セクション、
    `verbose: true` の生ログを目視確認した結果):
    - ロード成功 / 拒否 (falco が起動時に fatal error で落ちた) /
      警告のみで通過 (該当するものに丸をつけ、具体的なログ抜粋を記入):
  - 上記の仮説は 成立した / 成立しなかった (具体的な事象を記述):

---

## T1: 検知が行なわれること。cicd-sensor ではプロセス kill が実際に発生すること

### falco-live.yml

- run URL:
- preflight ステップ (Docker Hub タグ実在確認) の結果 (両バージョンとも成功したはず。失敗した場合は原因を記入):
- `falco-version: 0.39.0` の結果:
  - `Start Falco` ステップの outcome:
  - required_engine_version (0.43.0) との不整合は実際に問題になったか (はい/いいえ、具体的な事象):
  - 発火したルール (job summary から転記):
- `falco-version: 0.39.2` の結果:
  - `Start Falco` ステップの outcome:
  - required_engine_version (0.43.0) との不整合は実際に問題になったか (はい/いいえ、具体的な事象):
  - 発火したルール:
- シナリオごとの検知有無:

| シナリオ | 検知されたルール | 備考 |
| --- | --- | --- |
| 00-seed | | |
| 01-credential-access | | |
| 02-exfil | | |
| 03-npm-postinstall | | |
| 04-persistence | | |
| 05-memfd-exec | | |
| 06-anti-forensics | | |

### falco-analyze.yml

- run URL:
- preflight ステップ (Docker Hub タグ `0.39.2` 実在確認) の結果:
- `upload_raw_capture`: true / false
- `Analyze capture` ステップの outcome (`continue-on-error: true` のため、失敗しても後続は実行される):
- required_engine_version 0.43.0 のルールを 0.39.2 エンジンが実際にロードできたか (上の調査結果セクション参照):
- 発火したルール:
- シナリオごとの検知有無 (falco-live.yml と同じ形式で記入):

### sensor-monitor.yml (`monitor_mode: true`)

- run URL:
- 発火した検知ルール (Detection Log から転記):
- シナリオごとの検知有無:

| シナリオ | 検知されたルール | 備考 |
| --- | --- | --- |
| 00-seed | | |
| 01-credential-access | | |
| 02-exfil | | |
| 03-npm-postinstall | | |
| 04-persistence | | |
| 05-memfd-exec | | |
| 06-anti-forensics | | |
| 07-rule-markers (testbed_detect_marker / testbed_collect_marker) | | |

### sensor-enforce.yml (`monitor_mode: false`, kill テスト)

- run URL:
- `enforce` ジョブ (`killme` ステップ) の outcome:
- `REACHED_AFTER_KILLME` が観測されたか:
- `assert` ジョブの結果: 成功 (kill 確認できた) / 失敗 (kill されなかった、要調査)
- **このワークフローは成功が正常。** 失敗していた場合の原因調査メモ:

### 03-npm-postinstall (プロセス系譜の検知能力比較)

TEST-PLAN.md の仮説 (falco-actions のルールは系譜を条件に使っていないため汎用ルールでしか
引っかからないはず。cicd-sensor は npm の子孫であることを条件にできるため、より特化した
検知ができるはず) が実際に成り立ったか:

- falco 側の検知結果:
- cicd-sensor 側の検知結果:
- 仮説との一致: 一致 / 不一致 (不一致の場合、詳細を記述)

---

## T2: 実際にどのような情報が取得・閲覧できるか

### falco-actions

- live モード: job summary に含まれていた情報の種類:
- analyze モード: `telemetry-falco-analyze` に含まれていた情報の種類 (processes / connections / dns / containers / written-files / hashes / chisels):
- OpenAI / VirusTotal 連携: 使用した / しなかった (使用した場合、追加で得られた情報):

### cicd-sensor

- standalone モードの HTML レポートに含まれていた情報の種類:
- attestation predicate (`predicate.json`) の内容の概要:
- Manager は構築していない (このリポジトリの方針どおり)。

### 総評

falco-actions と cicd-sensor で、閲覧できる情報の粒度・種類にどのような違いがあったか:

---

## T3: public repo で動かした際に secret 情報が漏れないか

### 走査は成立したか (`render-matrix.py` の exit code)

まずこれを確認する。`render-matrix.py` の exit code が **2 (走査不成立)** だった場合、
以下のマトリクスは埋めず、このセクションのみ記入して T3 は再実行すること
(走査対象アーティファクトが無かった状態でのマトリクスは意味を持たない)。

- exit code (0 / 1 / 2 のいずれか):
- exit code が 2 (走査不成立) だった場合:
  - job summary / ログに出た `scanned_file_count` / `scan_root`:
  - `Verify downloaded artifacts are not empty` ステップは通過したか (通過している場合、
    ダウンロードされたファイルはあるが `scan-leaks.sh` の除外ロジックで全て除外された可能性がある):
  - 対象にした run_id (`${{ inputs.run_id }}`) は正しかったか、その run は
    telemetry-* アーティファクトを実際にアップロードしていたか:
  - 再実行の要否・再実行結果:

`leak-scan.yml` の実行結果 (job summary のマトリクスをそのまま転記、または要約。
exit code が 2 だった場合はこの表は「N/A (走査不成立)」と記入してよい):

| カナリア ID | 注入経路 | 期待 | 実測 | 判定 |
| --- | --- | --- | --- | --- |
| `CANARY_ENV` | 環境変数 | 漏れない | | |
| `CANARY_FILE` | ファイル内容 | 漏れない | | |
| `CANARY_PATH` | ファイルパス | 漏れる | | |
| `CANARY_ARGV_SHORT` | argv (短) | 漏れる | | |
| `CANARY_ARGV_LONG` | argv (長) | 漏れない | | |
| `CANARY_ARGV_FLAG` | argv (Authorization ヘッダ) | 漏れない | | |
| `CANARY_URL_QUERY` | HTTP クエリ | 漏れない | | |
| `CANARY_URL_PATH` | HTTP パス | 漏れる | | |
| `CANARY_DNS` | DNS ラベル | 漏れる | | |
| `CANARY_SCAP` | 生 syscall バッファ | `capture.scap` でのみ漏れる | | |

`CANARY_SCAP` は falco 固有 (§3「適用範囲」)。`sensor-monitor.yml` の run のみを
対象に走査した場合、実測欄は N/A (対象外) になる。これは正常であり、⚠️ や乖離
としては扱わない (docs/SPEC.md §7)。

さらに、`sensor-monitor.yml` の run で attestation predicate (`cicd-sensor-attestation`)
しか取得できていない場合 (HTML レポート `cicd-sensor-report` や falco の詳細テレメトリが
無い場合)、`CANARY_PATH` / `CANARY_FILE` / `CANARY_ARGV_SHORT` / `CANARY_ARGV_LONG` /
`CANARY_ARGV_FLAG` / `CANARY_URL_QUERY` / `CANARY_URL_PATH` の実測欄も
N/A (この証跡粒度では観測不能) になる (`CANARY_DNS` は predicate だけでも判定対象なので
対象外)。これも正常であり、⚠️ や乖離としては扱わない
(docs/SPEC.md §3「観測に必要な証跡粒度」、§7)。上記「参考: 初回実行で得られた結果」を参照。

`leak-scan.yml` は⚠️ が1つでもあれば非ゼロ終了する (exit 1)。今回の実行は
成功 (exit 0、すべて仮説どおり) / 失敗 (exit 1、乖離あり) / 走査不成立 (exit 2、上のセクション参照)
のどれだったか:

### ランナー由来トークンの検出 (`runner_token_findings`、参考情報・exit code に影響しない)

job summary の「ランナー由来トークンのパターン検出」セクションをそのまま転記、
または要約 (実値は記録されないため、件数とファイル名のみでよい):

| パターン | 検出件数 | 検出ファイル | 備考 (どのワークフロー/どのツールの出力か) |
| --- | --- | --- | --- |
| GitHub トークン (`ghs_`/`ghp_`/`gho_`/`ghu_`/`ghr_`) | | | |
| JWT (`eyJ...`、`ACTIONS_RUNTIME_TOKEN` 等) | | | |

- `capture.scap` (falco-analyze, `upload_raw_capture: true` のとき) から検出されたか:
- 検出された場合、`GITHUB_TOKEN` (`contents: read`、ジョブ完了時に失効) と
  `ACTIONS_RUNTIME_TOKEN` (run 中のみ有効) のどちらに該当すると考えられるか:

### 仮説との突き合わせ

上記マトリクスで「判定」が ⚠️ になった項目について、なぜ仮説と実測が食い違ったのかの
考察:

| カナリア ID | 乖離の内容 | 考えられる原因 | 追加調査の要否 |
| --- | --- | --- | --- |
| | | | |

### `CANARY_ENV` シークレットについて

- Secret は登録されていたか:
- 登録されていた場合、`CANARY_ENV` の判定結果 (漏れなかったか):
- 未登録だった場合、その旨が `scenarios/lib/common.sh` の記録どおりログに残っていたか:

---

## 参考: 初回実行で得られた結果 (run 32381640678, sensor-monitor.yml)

このセクションは記入用テンプレートではなく、実際に得られた実測結果の記録。
以降の実行結果とこの記録を突き合わせることで、再現性や差分を確認できる。

- 対象 run: `sensor-monitor.yml` の run
  [32381640678](https://github.com/fiord/cicd-runtime-testbed/actions/runs/32381640678)
- アーティファクトの中身: `cicd-sensor-attestation/predicate.json` の **1 ファイルのみ**
  (2112 バイト)。`cicd-sensor-report` (HTML レポート) も `testbed-log.jsonl` も
  含まれていなかった。
- cicd-sensor は正常に動作し、predicate の
  `https://cicd-sensor.github.io/runtime_trace/result/v1alpha1` は `"detected"`。
- 発火した検知:
  - カスタムルール `cicd_runtime_testbed/kill_test` / `testbed_detect_marker`
    (`.cicd-sensor/rules/` のロードが機能していることを確認)
  - ベースラインルール `cicd_sensor_baseline/generic_credential_access` /
    `anchored_multi_family_credential_access`
    (`01-credential-access.sh` の検知を確認)
- `CANARY_DNS` の漏洩を確認: predicate の `domains` 配列に
  `cnry-dns-donotuse-18ebf5.test.invalid.zuup3ixw3die3n0bckkvpevybe.bx.internal.cloudapp.net`
  として現れていた。DNS 名がリゾルバによって**小文字化**され、resolver の
  **search domain が付加**されていることを実地で確認 (`tools/scan-leaks.sh` の
  大文字小文字非依存化の直接の根拠。部分一致で拾えているため search domain の
  付加自体は問題にならない)。
- `testbed_collect_marker` は predicate に一切現れなかった。**`collect` アクションの
  ヒットが attestation predicate から除外される仕様であることを実地で確認**
  (docs/SPEC.md §4, §6)。
- `testbed_detect_marker` は `file_open` ルールだが、predicate には**どのファイルへの
  アクセスだったかの情報が無かった**。**`fileAccess` フィールドが未実装であることを
  実地で確認** (docs/SPEC.md §6)。
- 接続先 IP に `127.0.0.53` (systemd-resolved のループバックアドレス) が記録されており、
  ローカル DNS リゾルバ経由の名前解決が捕捉されていることを確認。
- この実測結果が、今回のツール改修 (カナリア走査の大文字小文字非依存化、
  collect-telemetry の完全性チェック、証跡粒度による N/A 判定) の直接のきっかけとなった。

---

## 実測結果（run 32519409901, sensor-monitor.yml）

このセクションも記入用テンプレートではなく、実際に得られた実測結果の記録。
**本テストベッドの主要な成果**。9 カナリア中 8 件が仮説どおりの結果になった。

| カナリア | 仮説 | 実測 | 判定 |
| --- | --- | --- | --- |
| `CANARY_ARGV_SHORT`（12バイト） | 漏れる | **漏れた** | 仮説どおり。redaction のキーワード依存の穴を実証 |
| `CANARY_ARGV_LONG`（13バイト以上） | 漏れない | 漏れなかった | 仮説どおり。12バイト超の切り詰めが機能 |
| `CANARY_ARGV_FLAG` | 漏れない | 漏れなかった | 仮説どおり。フラグ名ベースの redaction が機能 |
| `CANARY_PATH` | 漏れる | **漏れた** | 仮説どおり。ファイルパスは redact されない |
| `CANARY_DNS` | 漏れる | **漏れた** | 仮説どおり。ドメイン名は redact されない |
| `CANARY_FILE` | 漏れない | 漏れなかった | 仮説どおり。ファイル内容は読まれない |
| `CANARY_ENV` | 漏れない | 漏れなかった | 仮説どおり |
| `CANARY_URL_PATH` / `CANARY_URL_QUERY` | — | 観測不能 | `http_request` 未対応バージョンのため判定保留 |
| ランナー由来トークン（`ghs_` / JWT） | — | **検出 0 件** | cicd-sensor の出力に GitHub 発行トークンの混入は見られなかった |

### `CANARY_URL_PATH` / `CANARY_URL_QUERY` が観測不能だった原因

`http_request`（平文 HTTP 捕捉）の実装が入ったのは **2026-08-11**
（cicd-sensor リポジトリの commit `bdec37f2`
"feat(agent): capture cleartext HTTP request metadata (#139)"）で、
このテストベッドがピン留めしている **`cicd-sensor-action@6511eb44...`
(v0.0.38) は 2026-06-13** の時点のもので、
`internal/agent/bpf/http_hooks.bpf.h` を**含まない**。
**リリース済みタグの最新 `releases/v0.0.45` (2026-08-09) でもまだ未対応**で、
`http_request` は現時点では main ブランチにしか存在しない。

実際のこの run の `rules_summary` は `{"rule_count": 65, "warnings_count": 1}`
で、警告 1 件がこの未対応ルール (`testbed_canary_http_host`) に対応すると
考えられる。`cicd-sensorctl rule validate`（HEAD からビルドしたもの）は
通ってしまうため、この不整合は**ローカル検証では気づけない**。

**重要: `CANARY_URL_QUERY` の以前の ✅ は無効な確認だった。** 以前は
`CANARY_URL_QUERY` が「期待=漏れない / 実測=漏れない → ✅」と記録されて
いたが、これはクエリ文字列が実際に除去されたからではなく、**HTTP イベント
がそもそも捕捉されていなかったから** だった。典型的な「証拠の不在を証拠
として扱う」誤りであり、この ✅ には根拠が無い。今回のツール改修
（`tools/render-matrix.py` への「必要なイベント型サポート」による N/A 判定
の追加、`tools/scan-leaks.sh` への `sensor_capabilities` 抽出の追加）は、
この誤判定を二度と出さないようにするためのもの。

### `hits[]` から確認できたその他の事実

- 17 件のヒット。`testbed_canary_argv_carrier`（`process_exec`）5件、各種
  `credential_read`、`anchored_multi_family_credential_access`
  （相関ルール）、`shell_rc_write`（永続化）など。
- argv は **12 バイト超の要素がすべて `<truncated, N bytes>` に切り詰められる**
  （秘密らしさに関係なく一律。例:
  `"scenarios/07<truncated, 28 bytes>"`）。
- **ファイルパスと `exec_path` は切り詰めも redact もされない**
  （フルパスで記録される）。
- `collect` アクションのヒットは **HTML レポートには載るが attestation
  predicate には載らない**（run 32381640678 に続き、今回も確認）。

---

## 実測結果（run 32544606013, sensor-enforce.yml）— kill されなかった

このセクションも記入用テンプレートではなく、実際に得られた実測結果の記録。
**T1 (kill テスト) が失敗した run であり、このリポジトリで初めて
`sensor-enforce.yml` の `assert` ジョブが失敗した実例**。

- 対象 run: `sensor-enforce.yml` の run
  [32544606013](https://github.com/fiord/cicd-runtime-testbed/actions/runs/32544606013)
  (commit `ffb7b46`)。
- **結果: kill されなかった。** `scenarios/90-killme.sh` の実行ログに
  `REACHED_AFTER_KILLME` が出力され (`killme` ステップの outcome は
  `success`)、`assert` ジョブは設計どおり失敗した。

### 原因: `testbed_canary_http_host` (`event_type: http_request`) がプロジェクト設定全体を破棄した

`Start cicd-sensor` ステップの実ログ:

```
==> Loaded .cicd-sensor/config.yaml from repo
OK: 1 file(s) bundled into /home/runner/work/_temp/cicd-sensor-config/rules.bundle.yaml
error: bundle: ruleset_id=cicd_runtime_testbed/canary_observability rule_id=testbed_canary_http_host: unsupported event type "http_request"
rule validate: bundle failed validation
##[warning]project config fetch failed: /home/runner/work/_temp/cicd-sensor-staging/extracted/cicd-sensorctl-linux-amd64 exited with status 1; agent will run with baseline rules
==> Registering project start
```

- ワークフローの `Install cicd-sensorctl` ステップは `gh release download
  v0.0.38 --repo cicd-sensor/cicd-sensor` に失敗し (`::warning::failed to
  download cicd-sensorctl`)、`Validate .cicd-sensor/rules` ステップは
  (当時の実装では) 警告のみでスキップされていた。そのためローカルの
  `cicd-sensorctl rule validate` はそもそも実行されず、この不整合を
  ワークフロー内で事前に検出できなかった。
- `cicd-sensor-action` は `cicd-sensor-version` 入力を明示していないため
  既定値が使われ、実際にダウンロードされた agent は **v0.0.45**
  (2026-08-09) だった。以前の記録では v0.0.38 と混同していたが誤り
  (action 本体のピン留めタグが v0.0.38 であることと、agent バイナリの
  バージョンは別物)。v0.0.45 も `http_request` (実装は 2026-08-11) 未対応
  であるため、結論自体は変わらない。
- attestation predicate (`cicd-sensor-attestation/predicate.json`) と HTML
  レポート (`cicd-sensor-report.html`) の両方で、`testbed_kill_marker`
  ルールが **`action: detect`** として記録されていた
  (`ruleset_id: cicd_runtime_testbed/kill_test`)。`monitor_mode: false`
  (このワークフローが `.cicd-sensor/config.yaml` に書き込んだ値) が
  agent に反映されていなかったことの直接証拠。
- `rules_summary` は `{"rule_count": 65, "warnings_count": 1}`
  (run 32519409901 の `sensor-monitor.yml` と同一の値)。

### 対応 (この commit で実施)

1. `.cicd-sensor/rules/testbed.yaml` の `testbed_canary_http_host` を
   コメントアウトして無効化 (削除はしない。`canary_observability`
   ruleset 自体と、兄弟ルール2本は維持)。
2. `sensor-monitor.yml` / `sensor-enforce.yml` の `Validate .cicd-sensor/rules`
   ステップを、検証失敗時にジョブを失敗させるように変更 (`cicd-sensorctl`
   自体の入手に失敗した場合は従来どおり警告のみで続行するが、job summary
   に「検証をスキップした」ことを明記する)。
3. `sensor-enforce.yml` の `assert` ジョブに、`testbed_kill_marker` の実際の
   `action` を attestation predicate / HTML レポートから読み取って job
   summary に出すステップを追加。`action` が `detect` の場合は `::error::`
   で `monitor_mode` / プロジェクト設定フェッチ失敗の可能性を明示する。

### 教訓

**未対応のイベント型を使うルールが1本でもあると、それとは無関係な他の
カスタムルールや `monitor_mode` の意味まで変わってしまう。** ローカルの
`cicd-sensorctl rule validate` (HEAD からビルドしたもの) はこの不整合を
検出できない (むしろ通ってしまう) ため、実際に GitHub Actions 上で走らせて
job summary / ジョブログを確認するまで気づけない。README.md「既知の制約」
を参照。

---

## 総合所見

- T1 / T2 / T3 を通じて得られた、falco-actions と cicd-sensor それぞれの強み・弱み:
- 次に検証すべきこと (フォローアップ課題):
