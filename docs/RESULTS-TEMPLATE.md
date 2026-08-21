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

## 総合所見

- T1 / T2 / T3 を通じて得られた、falco-actions と cicd-sensor それぞれの強み・弱み:
- 次に検証すべきこと (フォローアップ課題):
