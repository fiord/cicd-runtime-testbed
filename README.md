# cicd-runtime-testbed

`falcosecurity/falco-actions` と `cicd-sensor` を実際に GitHub Actions 上で動かし、

- **T1**: 検知が行なわれるか。cicd-sensor では、実際にプロセス kill が起きるか
- **T2**: 実際にどのような情報が取得・閲覧できるか
- **T3**: public repo で動かした際に secret 情報が漏れないか

の3点を実地で確認するためのテスト用リポジトリです。

**このリポジトリは検証用です。production ワークフローにそのまま組み込むものではありません。**
詳しい設計契約は [`docs/SPEC.md`](docs/SPEC.md) を、安全上の注意点は [`docs/SAFETY.md`](docs/SAFETY.md) を参照してください。

実測結果に基づく既知の不備と、本来やりたい比較テストを成立させるために必要な修正は
[`docs/REQUIRED-FIXES.md`](docs/REQUIRED-FIXES.md) にまとめてあります
(upstream `falcosecurity/falco-actions` 側の修正案を含む)。

---

## ⚠️ 重要な警告

- **`falco-analyze.yml` は public リポジトリで実行してよく、ジョブを停止するガードはありません。**
  このワークフローは T3 の検証で「`capture.scap` から実際に情報が漏れること」を
  観測するために存在します。つまり漏洩を再現するのが目的であり、漏洩して当然の作りです。
  以前のバージョンには「public かつ `upload_raw_capture: true` ならジョブを停止する」
  ガードがありましたが、過剰と判断して撤去しました。判断根拠:
  - `capture.scap` に入りうるカナリア値はすべて偽物で、リポジトリにコミット済みです。
    公開されても失うものがありません。
  - このワークフローが実際に持つ本物の認証情報は次の2つだけです。
    - `GITHUB_TOKEN`: 宣言している権限は `contents: read` のみ。public リポジトリでは
      誰でも読み取れる情報に対する権限に過ぎず、ジョブ完了時に失効します。
    - `ACTIONS_RUNTIME_TOKEN`: run 中のみ有効な内部トークン。悪用の本命経路は
      `actions/cache` への汚染ですが、このリポジトリは `actions/cache` を
      使っていないため、その経路自体が存在しません。
  - `id-token: write` を宣言していないため `ACTIONS_ID_TOKEN_REQUEST_TOKEN` は存在しません。
  - 残るリスクは「このテストリポジトリ自身のアーティファクトを他人が上書きできるかも
    しれない」程度であり、検証価値のほうが上回ります。
  - `falco-actions` の stop action (analyze モード) は `capture.scap` を**無条件に**
    アップロードします。この動作を抑止する入力は存在せず、元リポジトリは変更しないため、
    このワークフローは「アップロード直後に GitHub API で削除する」方式で緩和しています。
    ただし削除が完了するまでの**数秒〜数十秒は、public リポジトリでは誰でも
    ダウンロードできる状態**になります。
  - `upload_raw_capture: true` にすると、`capture.scap` は
    `telemetry-falco-analyze` として `retention-days: 1` の間ずっと取得可能になります。
    `capture.scap` には `CANARY_SCAP` のような、他の経路では漏れないはずの値も
    含まれる想定です (docs/SPEC.md §3)。
  - public リポジトリで実行すると、`Notice: raw capture exposure on a public repository`
    ステップが `::warning::` 注釈と job summary で「この run の `capture.scap` には
    何が入るか」を具体的に告知します。**ジョブは停止しません。**
  - **再評価が必要な条件**: リポジトリに本物の secret を追加した場合、
    `contents: write` / `id-token: write` を宣言した場合、`actions/cache` を
    使い始めた場合は、この判断 (public で実行してよいこと) を見直してください。
  - 他の4本 (`falco-live.yml` / `sensor-monitor.yml` / `sensor-enforce.yml` /
    `leak-scan.yml`) は生キャプチャを扱わないため、public でも実行できます。
- **`sensor-enforce.yml` だけは「成功が正常」です。** 他の4本のワークフロー
  (`falco-live.yml` / `falco-analyze.yml` / `sensor-monitor.yml` / `leak-scan.yml`) は、
  検知結果を集めること自体が目的なので、ジョブが赤くなっても異常ではありません。
  しかし `sensor-enforce.yml` は「cicd-sensor が実際にプロセスを kill すること」を検証する
  ワークフローで、`assert` ジョブが **成功** することが「kill が確認できた」ことを意味します。
  `assert` が失敗した場合は、kill が実際には起きなかったことを意味し、それが異常事態です。
- 全てのトリガーは `workflow_dispatch` のみです。`push` / `pull_request` では起動しません
  (public repo で不用意に走らないようにするため)。
- **カナリア走査 (`tools/scan-leaks.sh`) は大文字小文字を区別しません。** DNS 名は
  リゾルバによって小文字に正規化されるため、以前の大文字小文字を区別する実装では
  `CANARY_DNS` の漏洩を見逃す偽陰性が実地実行 (run 32381640678) で発生していました。
  ランナー由来トークンの二次走査 (`runner_token_findings`) は対象外で、引き続き
  大文字小文字を区別します (`ghs_`/`ghp_` 等のプレフィックスや JWT の `eyJ` は大小に
  意味があるため)。
- **cicd-sensor の standalone モードで得られる証跡には限界があります。** attestation
  predicate は集計のみで、個別イベントの timestamp / argv / プロセスツリー、
  ファイルアクセスのパス (`fileAccess` 未実装)、`collect` アクションのヒット、HTTP の
  path/host を一切含みません。個別イベントの詳細ログを得るには Manager が必要で、
  このテストベッドは Manager を構築しない方針のため得られません。このため
  `tools/render-matrix.py` は、集計レベルの証跡 (predicate.json) しか無い場合、
  そのレベルでは原理的に観測できないカナリアを ⚠️ ではなく **N/A (この証跡粒度では
  観測不能)** と表示します (`CANARY_DNS` は predicate の `domains` 配列に載るため
  集計レベルでも判定対象です)。実地実行 (run 32381640678) では、実際にアーティファクトが
  `cicd-sensor-attestation/predicate.json` 1 ファイルだけだったことをこの仕組みで
  正しく扱えることを確認しています (docs/SPEC.md §3, §6, §7)。
- **collect-telemetry 系ジョブはテレメトリ収集の完全性を明示します。** 期待する
  アーティファクト／抽出ファイルのうちどれが取得できたかを job summary と
  `telemetry-manifest.txt` (各 telemetry アーティファクトに同梱) に記録し、1 つも
  取得できなければジョブを失敗させます (一部だけの場合は `::warning::` で続行)。
  以前は `actions/download-artifact` の `continue-on-error: true` により、
  `cicd-sensor-report.html` の取得に失敗しても黙って進み、predicate.json 1 ファイルだけの
  テレメトリが「成功」として上がってしまう不具合がありました (run 32381640678 で実際に発生)。
- **cicd-sensor はルールに一致したイベントの詳細しか記録しません。**
  実物の HTML レポート (run 32510077347) を解析して判明した最重要の事実です。
  standalone モードのレポートには「生のイベントストリーム」に相当するものが
  存在せず、`hits[]` (ルールに一致したイベント) だけが `process.argv` /
  `process.ancestors` / `payload` の詳細を持ちます。`domain_observations[]` /
  `network_connections[]` はルール一致に関係なく載りますが `argv` を持ちません。
  このため、以前は `CANARY_ARGV_SHORT` / `CANARY_ARGV_LONG` がそもそも
  どのシナリオの argv にも注入されておらず (仕様の穴)、さらに argv・
  `CANARY_PATH` のパス・HTTP の path/query を運ぶプロセスやイベントが
  何のルールにも一致しないため記録されない、という二重の問題がありました。
  `02-exfil.sh` に argv カナリアの注入を追加し、`.cicd-sensor/rules/testbed.yaml`
  に `action: collect` の観測用ルール 3 本 (`testbed_canary_argv_carrier` /
  `testbed_canary_path_probe` / `testbed_canary_http_host`) を追加して
  対応しています (docs/SPEC.md §4, §5 参照)。
- **アーティファクト名の不一致を修正しました。** `cicd-sensor-action` が
  アップロードする HTML レポートの実際のアーティファクト名は
  `cicd-sensor-report.html` です (`gh api` で実際の run から確認済み)。
  以前のワークフローは `cicd-sensor-report` (拡張子なし) でダウンロードを
  試みており、常に失敗していました (`continue-on-error: true` で黙って
  `MISSING` として処理は続行していましたが、HTML レポートが一度も
  取得できていませんでした)。`cicd-sensor-attestation` の名前は元々正しく、
  変更していません。
- **カナリアには「採点対象 (scored)」と「参考情報 (informational)」の区別があります。**
  実地実行 (run 32643269616。falco-live の run 32625231129 に対する leak-scan) で、
  `CANARY_PATH` / `CANARY_ARGV_SHORT` / `CANARY_DNS` / `CANARY_SCAP` の4件が ⚠️
  (乖離) と判定される問題が見つかりましたが、これは真の発見ではありませんでした。
  これらのカナリアは「cicd-sensor の redaction 挙動 (argv 切り詰め、キーワード依存の
  redaction、パスの非 redact 等) を検証するために設計されたもの」であり、
  redaction 層を持たない falco に同じ期待値を適用して採点していたのが誤りでした。
  falco の出力はルールの `output:` テンプレートに書かれた内容がそのまま出るだけで、
  「カナリアが現れるか」はどのルールが発火したかで決まる、cicd-sensor とは別の問いです。
  `tools/render-matrix.py` は、`CANARY_ENV` / `CANARY_FILE` を除く8個のカナリアについて、
  falco に対しては informational (検出の有無は表示するが ✅/⚠️ を付けず exit code にも
  算入しない) として扱うようになりました。合わせて `CANARY_SCAP` の証跡粒度要求を
  「詳細以上」から「生 (`capture.scap` そのもの)」に修正しました (以前はこのチェックの
  対象外で、`capture.scap` の無い falco live モードに対して誤って ⚠️ になっていました)。
  詳細は docs/SPEC.md §3・§7 参照。

---

## 既知の制約

### 🚨🚨 最も根本的な事実: 設定・ルールはワークスペースではなくコミット SHA から取得される（実行時の書き換えは効かない）

このリポジトリの以前の設計には、これより下の全ての「既知の制約」の前提を
覆す誤りがありました。**必ず最初に読んでください。**

`cicd-sensor-action` は、プロジェクト設定 (`.cicd-sensor/config.yaml`) と
カスタムルール (`.cicd-sensor/rules/`) を、ジョブのワークスペース上の
ファイルからではなく **GitHub Contents API 経由でコミット SHA
(`GITHUB_SHA`) から取得します。** 根拠 (cicd-sensor-action v0.0.38,
commit `6511eb44c91d71b2b93d71193b1bf2cb18352f66`, `src/main.js:643-666`):

```js
const repo = process.env.GITHUB_REPOSITORY || '';
const ref  = process.env.GITHUB_SHA || '';
if (repo && ref) {
  const cfg = await fetchRepoFile(githubToken, repo, ref, '.cicd-sensor/config.yaml');
  ...
  const ruleFiles = await fetchRepoDirectoryFiles(githubToken, repo, ref, '.cicd-sensor/rules');
```

以前の `sensor-monitor.yml` / `sensor-enforce.yml` は、`actions/checkout` の
後にジョブ内で `.cicd-sensor/config.yaml` を `cat > ... <<'EOF'` で書き換え、
`sensor-monitor.yml` では `monitor_mode: true` のまま、`sensor-enforce.yml`
では `monitor_mode: false` に切り替えるつもりでした。しかし action は
ワークスペース上のこの変更を一切見ないため、**この書き換えステップは完全に
無意味 (no-op) でした。** 実際に使われていたのは常にリポジトリに
コミットされている値 (`monitor_mode: true`) であり、これが原因で
`sensor-enforce.yml` の `testbed_kill_marker` (`action: terminate`) が
`action: detect` に降格され、kill が起きませんでした
(run 32544606013, 32545681004 の両方で実機確認)。両ワークフローの
当該ステップは削除し、削除理由のコメントを残しています。

**この挙動自体は cicd-sensor の良い設計です。** ジョブ内で実行される
プロセス (侵害されている可能性のあるビルドスクリプトや依存パッケージの
postinstall なども含む) が、ワークスペース上の `monitor_mode` やカスタム
ルールを書き換えて自分自身への監視を無効化する、という攻撃を構造的に
防いでいます。監視設定がジョブから独立した信頼できる場所 (コミット SHA)
から取得されるのは、セキュリティ上むしろ正しい設計です。

この帰結として、**`monitor_mode` はリポジトリ全体で1つの値しか持てず、
`sensor-monitor.yml` と `sensor-enforce.yml` の間で切り替えることはできません。**
このリポジトリでは kill テスト (`sensor-enforce.yml`) を機能させることを
優先し、`.cicd-sensor/config.yaml` のコミット値そのものを
`monitor_mode: false` にしています。これにより `sensor-monitor.yml` でも
terminate ルールが有効になりますが、影響を評価した結果は次のとおりです。

- 自作ルールで `action: terminate` を持つのは `testbed_kill_marker` のみ。
  発火条件の `cicd-sensor-killme.marker` への書き込みは
  `scenarios/90-killme.sh` (`sensor-enforce.yml` 専用) だけが行なうため、
  `sensor-monitor.yml` では発火しません。
- ベースラインルール (`cicd-sensor/rules/`) で `action: terminate` を
  持つのは、実際にリポジトリを読んで列挙した次の7件のみです:
  `docker_upstream_socket_access` (`docker-upstream.sock` への
  `unix_socket_connect`)、`mini_shaihulud_antv_c2_domain` /
  `mastra_npm_compromise_c2_ip` / `asyncapi_npm_compromise_c2_ip` /
  `asyncapi_miasma_dht_bootstrap_domain` / `miasma_systemd_unit_write` /
  `keyv_shaihulud_math_symbol_artifact`。`sensor-monitor.yml` の
  `scenarios/00〜07` は、実在の IOC ドメイン・IP に一切通信せず
  (通信先は `example.com` と `*.test.invalid` のみ)、
  `docker-upstream.sock` にもアクセスせず、`systemd` 配下に `miasma` を
  含むパスへの書き込みも `node_modules/keyv/Math_Symbol.js` の読み書きも
  行なわないため、現状これらは発火しません。
- **ただし、万一 `sensor-monitor.yml` のシナリオが将来変更されて上記
  いずれかのベースライン terminate ルールの条件に触れた場合、
  `monitor_mode: false` の下では実際にそのジョブが kill されるリスクが
  残ります。** これは正直に記載しておきます。

詳細は `docs/SPEC.md` §5 と `.cicd-sensor/config.yaml` のコメントを
参照してください。

### 🚨 最重要: 無効なルールが1本あるだけでプロジェクト設定全体 (`monitor_mode` を含む) が破棄される

実地実行 (**run 32544606013**, `sensor-enforce.yml`) で判明した、**このリポジトリ
全体の運用における最大の落とし穴**です。**必ず読んでください。**

`.cicd-sensor/rules/` に `event_type` がそのバージョンの cicd-sensor に
未対応のルールが**1本でも**あると、cicd-sensor-action 内部のプロジェクト設定
フェッチ (config.yaml + ルールバンドルの検証) が**丸ごと失敗**し、
`.cicd-sensor/config.yaml` の `monitor_mode` を含む**プロジェクト設定全体**が
agent に届かなくなります。実際のジョブログ (`sensor-enforce.yml` の
`Start cicd-sensor` ステップ、run 32544606013):

```
==> Loaded .cicd-sensor/config.yaml from repo
OK: 1 file(s) bundled into /home/runner/work/_temp/cicd-sensor-config/rules.bundle.yaml
error: bundle: ruleset_id=cicd_runtime_testbed/canary_observability rule_id=testbed_canary_http_host: unsupported event type "http_request"
rule validate: bundle failed validation
##[warning]project config fetch failed: /home/runner/work/_temp/cicd-sensor-staging/extracted/cicd-sensorctl-linux-amd64 exited with status 1; agent will run with baseline rules
==> Registering project start
```

この run は `sensor-enforce.yml` (`monitor_mode: false` を書き込んでいたはず)
だったが、上記の理由で `monitor_mode: false` が agent に届かず、
`testbed_kill_marker` ルール (`action: terminate` のはず) が attestation
predicate / HTML レポートの両方で **`action: detect`** として記録され、
`REACHED_AFTER_KILLME` がログに出力された (= **プロセスは kill されなかった**)。
`assert` ジョブは (設計どおり) この乖離を検出して失敗した。

**教訓**: たった1本の未対応イベント型ルールが、それとは無関係な他の
カスタムルールや `monitor_mode` の意味まで変えてしまう。

この不整合は、**`cicd-sensorctl` のバージョンを agent と一致させていれば
ローカルでも検出できます** (以前ここには「ローカル検証だけでは検出
できない」と書かれていましたが、それは HEAD からビルドした
`cicd-sensorctl` を使っていたための誤りでした)。実際、同一のルール
バンドルに対して:

```
$ cicd-sensorctl-0.0.46 rule validate .cicd-sensor/rules
OK: 1 file(s) bundled and validated                      # exit 0

$ cicd-sensorctl-0.0.45 rule validate .cicd-sensor/rules
error: bundle: ruleset_id=cicd_runtime_testbed/canary_observability rule_id=testbed_canary_http_host: unsupported event type "http_request"
rule validate: bundle failed validation                  # exit 1
```

そのため現在は、各ワークフローの `env: CICD_SENSOR_VERSION` を
`Install cicd-sensorctl` の download タグと cicd-sensor-action の
`cicd-sensor-version` 入力の**両方**に渡し、検証側と実行側のバージョンを
構造的に一致させています。それでも実際の run の `Start cicd-sensor`
ステップログに `##[warning]project config fetch failed` が出ていないか、
job summary の `rules_summary` を確認してください。
この教訓を踏まえ、`sensor-monitor.yml` / `sensor-enforce.yml` の
`Validate .cicd-sensor/rules` ステップは、検証に失敗した場合に
**そのステップ自体でジョブを失敗させる**ように変更済みです
(`cicd-sensorctl` の入手自体に失敗した場合は、従来どおり警告のみで続行し、
その旨を job summary に記録します)。

### `http_request` イベント型 (平文 HTTP 捕捉) — v0.0.46 で解消済み

上記「最重要」の事故の直接の原因になった制約です。**現在は解消しています**
が、バージョンを下げると再発するため経緯を残します。

- このリポジトリは `cicd-sensor-action@6511eb44c91d71b2b93d71193b1bf2cb18352f66`
  (action 本体のタグ v0.0.38、2026-06-13 時点のコミット) をピン留めして
  使っています。**ただしこれは action 本体のバージョンで、実際に
  ダウンロード・実行される cicd-sensor の agent バイナリのバージョンは
  別です。**
- 事故当時、ワークフローは action の `cicd-sensor-version` 入力を明示して
  いなかったため既定値が使われ、run 32544606013 の実ログで
  `cicd-sensor-version: v0.0.45` が実際に使われていたことを確認しました。
  `http_request` イベント (平文 HTTP リクエストの捕捉) の実装は
  **2026-08-11** (cicd-sensor の commit `bdec37f2` "feat(agent): capture
  cleartext HTTP request metadata (#139)") で、v0.0.45 (2026-08-09) には
  含まれていませんでした。
- **その後 v0.0.46 がリリースされ、`http_request` は正式に利用可能に
  なりました。** 両バージョンの `cicd-sensorctl` に同一のルールバンドルを
  渡して実験し、v0.0.45 は `unsupported event type "http_request"` で
  拒否、v0.0.46 は `OK` になることを確認済みです。以前ここに書かれていた
  「`http_request` は main ブランチにしか存在せず、リリース済みタグには
  含まれていない」という記述は**もはや正しくありません**。
- したがって現在、`.cicd-sensor/rules/testbed.yaml` の
  `testbed_canary_http_host` ルールは**有効化されています**。ワークフローは
  `env: CICD_SENSOR_VERSION: "v0.0.46"` を明示し、それを
  `cicd-sensor-version` 入力に渡します。
- **`CICD_SENSOR_VERSION` を v0.0.46 未満に下げる場合は、
  `testbed_canary_http_host` も同時に無効化しなければなりません。**
  そうしないと、上記「最重要」で説明したとおり、この1本のルールのせいで
  `monitor_mode` を含むプロジェクト設定全体が agent に届かなくなります。
- `CANARY_URL_PATH` / `CANARY_URL_QUERY` は、これにより **N/A から実測
  対象に戻ります**。過去のこのプロジェクトの記録で `CANARY_URL_QUERY` を
  ✅ (漏れない) としていたものは無効な確認でした (クエリ文字列が実際に
  除去されたからではなく、HTTP イベント自体が捕捉されていなかったため)。
  詳細は `docs/RESULTS-TEMPLATE.md` の「実測結果 (run 32519409901)」を
  参照してください。**v0.0.46 で実際に `http_request` イベントが記録され、
  カナリアが観測できることは、まだ CI 上で確認していません。**

---

## セットアップ

### 1. `CANARY_ENV` シークレットの登録

`canaries/canaries.env` の `CANARY_ENV` の値と **同じ値** を、リポジトリの Secrets に
`CANARY_ENV` として登録してください (Settings → Secrets and variables → Actions →
New repository secret)。

```
Name:  CANARY_ENV
Value: canaries/canaries.env に書かれている CANARY_ENV=... の値と同じもの
```

これは環境変数経由の漏洩 (T3) を検証するための唯一の Secrets 登録です。値自体は偽物
(`CNRY-` プレフィックス) で、本物の秘密情報ではありません。

Secret を登録しなくても他のシナリオは動きます。`CANARY_ENV` 経由の漏洩検証だけが
意味を持たなくなり、その旨が `scenarios/lib/common.sh` の `load_canaries` を通じて
実行ログに記録されます。

### 2. `falco-actions` の SHA を確定する

**`falcosecurity/falco-actions` には git タグが存在しません。** そのため、このリポジトリの
ワークフローには実在しない SHA を推測で書かず、次のプレースホルダを入れてあります。

```
falcosecurity/falco-actions/start@PIN_ME_SEE_README
falcosecurity/falco-actions/stop@PIN_ME_SEE_README
falcosecurity/falco-actions/analyze@PIN_ME_SEE_README
```

`falco-analyze.yml` の `analyze` ジョブは、falco-actions リポジトリ本体を
`ref: PIN_ME_SEE_README` でチェックアウトして同梱の CI/CD ルールファイル
(`rules/falco_cicd_rules.yaml`) を読む処理も含んでいます。こちらも同じ SHA に揃えてください。

**利用者がやること:**

1. https://github.com/falcosecurity/falco-actions のデフォルトブランチの最新コミット
   (または任意の固定したいコミット) の SHA を確認する。
2. `.github/workflows/falco-live.yml` / `falco-analyze.yml` 内の
   `PIN_ME_SEE_README` を、確認した SHA にすべて置換する
   (`uses:` の3箇所 + `ref:` の1箇所、行末コメントの `# UNPINNED: ...` は
   `# <確認した日付時点の最新コミット>` などに書き換える)。
3. `falco-analyze.yml` の `custom-rule-file` に渡している
   `_falco-actions-src/rules/falco_cicd_rules.yaml` が実際にそのパスに存在することを
   (チェックアウトしたコミットで) 確認する。

タグがない以上、この SHA は**時間とともに古くなります**。定期的に見直してください。

### 3. `cicd-sensorctl` の入手経路について (実機確認済み)

`sensor-monitor.yml` / `sensor-enforce.yml` は `cicd-sensorctl rule validate` を実行する前に、
`cicd-sensor/cicd-sensor` のリリースから `cicd-sensorctl` を取得します。

**リリースタグは `v0.0.45` ではなく `releases/v0.0.45` という形式です。** 旧版の
ワークフローはこれを `gh release download v0.0.38` (= 存在しないタグ。しかも
v0.0.38 は sensor 本体ではなく action 側のバージョン) と書いていたため、
**これまでの全 run で `release not found` になり、`Validate .cicd-sensor/rules`
ステップは一度も実行されていませんでした**。この検証さえ動いていれば、
run 32544606013 の「無効なルール1本でプロジェクト設定全体が agent に届かない」
事故は事前に防げていました (docs/REQUIRED-FIXES.md R-1)。

現在は以下を実行します (ローカルで実際に成功することを確認済み):

```sh
gh release download "releases/${CICD_SENSOR_VERSION}" \
    --repo cicd-sensor/cicd-sensor \
    --pattern "cicd-sensor_*_linux_amd64.tar.gz"
```

- アセット `cicd-sensor_<version>_linux_amd64.tar.gz` の中身は
  `cicd-sensorctl-linux-amd64` / `cicd-sensor-manager-linux-amd64` /
  `cicd-sensor-linux-amd64` の3バイナリです。
- `cicd-sensorctl version` というサブコマンドは**存在しません**
  (`unknown command: version`)。存在するのは `rule validate` / `rule bundle` /
  `token generate` / `report attest` / `report html` / `report stepsummary` です。
  旧版にあった `cicd-sensorctl version || true` は削除しました。
- バージョンは各ワークフロー冒頭の `env: CICD_SENSOR_VERSION` が単一の
  source of truth で、`Install cicd-sensorctl` の download タグと
  `cicd-sensor-action` の `cicd-sensor-version` 入力の両方に使われます。
  この2つがずれると、ローカル検証は通るのに agent 側ではバンドル検証が
  落ちる、という上記の事故が再発します。

このステップが失敗しても後続の `cicd-sensor-action` 自体は動きます (rule validate が
スキップされ、警告が出るだけです)。

---

## ワークフロー一覧

| ワークフロー | 目的 | 実行方法 | 期待される結果 |
| --- | --- | --- | --- |
| `falco-live.yml` | falco live モードでの検知、および upstream の cicd-rules マウントパスバグと fork 修正版の比較 | Actions タブから workflow_dispatch で実行 (入力なし) | `live` ジョブ (upstream falco-actions、`falco-version` 0.39.0 / 0.39.2 の matrix) と `live-forked` ジョブ (fork-fixed falco-actions、`falco-version` 0.44.1 固定) の**3 leg 構成**。falco-actions を呼ぶ前に、指定した `falco-version` タグが Docker Hub に実在するかを preflight ステップが両ジョブで確認する (存在しなければジョブをここで明確に落とす)。各 leg の `telemetry-falco-live-<version>` / `telemetry-falco-live-forked-0.44.1` アーティファクトに job summary と (取得できれば) `falco_events.json` / `falco_start_logs.txt` が入る。`required_engine_version: 0.43.0` のルールを upstream leg (上限バージョン 0.39.x) が読み込めたか/拒否したか/警告のみで通ったかを job summary の "matrix note" / "required_engine_version" セクションで確認する。**なぜ upstream leg は 0.39.x が上限か**: falco-actions がハードコードして使う `falcosecurity/falco-no-driver` イメージは、Docker Hub 上の数値タグが `0.39.2` で公開停止しているため (`0.43.0` は実在しない)。**upstream vs fork の比較**: upstream の `falcosecurity/falco-actions` は `start/action.yaml:70` で CI/CD ルールのマウント元パスを誤っており (`github.action_path` が `start/` を指すのに `rules/...` という相対パスを使っているため、実体である リポジトリ直下の `rules/` を指せず、CI/CD ルールが一度もロードされない)、`cicd-rules` は既定 `true` のためこれはデフォルト動作で検知が 0 件になるバグである。fork 修正版 (`fiord/falco-actions@fix/cicd-rules-mount-path`、修正の起点は commit 360d62c72985b790bff96abde043b14ae053efe5、https://github.com/fiord/falco-actions/commit/360d62c72985b790bff96abde043b14ae053efe5 ) はこのパスを `../rules/...` に修正しているだけでなく、使用イメージ自体も `falcosecurity/falco-no-driver` (メンテナンス終了) から、維持されている `falcosecurity/falco` に切り替えている。したがって `live-forked` leg は `falco-version: "0.44.1"` (falcosecurity/falco の Docker Hub 上の実際の最新、preflight ステップの対象リポジトリも `falcosecurity/falco` に変更済み) を指定でき、`required_engine_version: 0.43.0` を満たすエンジンで実行できる。この `live-forked` leg が検証したいのは (1) 維持されているイメージの新しい Falco が現在のランナーのカーネル (6.17) で起動し続けられるか、(2) `cicd-rules` のパス修正により CI/CD 特化ルールがロードされるか、(3) 実際に検知イベントが出るか、の3点。**注記 (検証用の一時的な例外)**: `live-forked` ジョブの action 参照は、このリポジトリの「`uses:` は全てコミット SHA でピン留めする」方針 (docs/SPEC.md §8、docs/SAFETY.md) に対する意図的な例外として、SHA pin ではなく上記の `fix/cicd-rules-mount-path` ブランチへの参照にしてある。参照先は自分 (fiord) が管理する fork のブランチであり、第三者のリポジトリではない。ブランチに継続的に追加修正を入れている最中のため、都度 SHA を追いかけて更新するのは非効率という判断による。**検証が完了し fork 側の修正が安定したら、必ずコミット SHA pin に戻すこと。** upstream (`falcosecurity/falco-actions`、`live` ジョブ) 側の参照は SHA pin のまま変更しない。両ジョブとも「CI/CD ルールがロードされたか」を起動ログから判定し job summary に出す (ジョブは失敗させない、観測目的) ので、`live` と `live-forked` の job summary を見比べれば影響が定量的にわかる |
| `falco-analyze.yml` | falco analyze モードでの検知と生キャプチャ | workflow_dispatch。`upload_raw_capture` (既定 false) で生キャプチャの取り扱いを制御 | `analyze` ジョブは falco-actions/analyze を呼ぶ前に、`falco-version: 0.39.2` (falcosecurity/falco-no-driver の実際の上限) が Docker Hub に実在するかを preflight ステップが確認する。`telemetry-falco-analyze` アーティファクトに job summary・抽出情報 (processes/connections/dns/containers/written-files/hashes) が入る。`upload_raw_capture: true` のときのみ `capture.scap` も含む。同梱ルール (`required_engine_version: 0.43.0`) を 0.39.2 エンジンが実際にロードできたかは job summary の "required_engine_version" セクションを参照 (要手動確認) |
| `sensor-monitor.yml` | cicd-sensor の検知 (自作ルールでの kill は起きない想定。ただし `monitor_mode` はコミット値 `false` でリポジトリ全体共通、詳細は既知の制約「🚨🚨 最も根本的な事実」参照) | workflow_dispatch (入力なし) | 全シナリオ (00〜07。07 は detect / collect ルール専用) が実行され、`telemetry-cicd-sensor-monitor` に HTML レポートと attestation predicate が入る。collect-telemetry ジョブは取得できたアーティファクトを `telemetry-manifest.txt` と job summary に明記し、1 つも取得できなければジョブを失敗させる |
| `sensor-enforce.yml` | cicd-sensor の kill 動作の検証。**成功が正常** | workflow_dispatch (入力なし) | `assert` ジョブが **成功** すれば kill が確認できたことを意味する。失敗した場合は kill が起きなかったことを意味し、要調査。**このワークフローが実行する `scenarios/90-killme.sh` はカナリアを注入しない** (`load_canaries` を呼ばない) ため、この run の run_id は `leak-scan.yml` の入力にはできない (対象外として弾かれる)。collect-telemetry ジョブのテレメトリ収集完全性チェックは `sensor-monitor.yml` と同様 |
| `leak-scan.yml` | 漏洩マトリクスの生成 (T3) | **workflow_run (自動)**: `falco-live.yml` / `falco-analyze.yml` / `sensor-monitor.yml` の完了で自動起動し、その run を対象にする。**workflow_dispatch (手動)**: `run_id` に上記いずれかの run ID を入力 (`sensor-enforce.yml` の run ID は不可。上記参照) | 対象 run の `telemetry-*` アーティファクトを横断的に走査し、job summary と (常に) ステップログの両方にカナリアごとの 期待 vs 実測 のマトリクスを出す。走査対象に含まれないツール向けのカナリア (`CANARY_SCAP` は falco 固有) は ⚠️ ではなく N/A (対象外) と表示され、判定にも exit code にも影響しない。**証跡の粒度が足りない場合も同様に N/A になる** (例: cicd-sensor の attestation predicate 集計のみで、HTML レポートや falco の詳細テレメトリが無い場合、`CANARY_PATH` 等の「詳細以上」を要求するカナリアは N/A (この証跡粒度では観測不能) と表示される。`CANARY_DNS` は predicate だけでも判定対象)。**終了コードが 2 種類あり、意味が異なる**: exit 1 = 期待と実測の乖離あり (「発見」。仮説と現実が食い違ったことを目立たせるための意図的な失敗で、job summary の ⚠️ 行と `::error::` 注釈にどのカナリアが食い違ったかが出る)、exit 2 = 走査不成立 (「テスト自体が成立していない」。対象 run に `telemetry-*` アーティファクトが無かった、または `sensor-enforce.yml` の run を誤って指定した等で走査対象 0 件/対象外になったケース。カナリアの判定は行なわれない)。どちらもワークフローとしては失敗 (赤) になるが、job summary の内容でどちらかを区別できる |

### 推奨実行順序

1. `sensor-monitor.yml` と `falco-live.yml` / `falco-analyze.yml` を先に実行し、検知結果とテレメトリを集める (T1 前半 / T2)。
2. `sensor-enforce.yml` を実行し、kill が実際に起きることを確認する (T1 後半)。
3. `leak-scan.yml` が 1 の各ワークフローの完了時に `workflow_run` で**自動起動**し、
   その run を対象に T3 を確認する (手動実行は不要)。
   過去の run を測り直したい場合だけ、1 で得た run_id
   (`sensor-monitor.yml` / `falco-live.yml` / `falco-analyze.yml` のいずれか。
   `sensor-enforce.yml` の run_id は使えない) を `workflow_dispatch` の
   `run_id` 入力に渡して手動実行する。

   > ⚠️ `workflow_run` トリガはデフォルトブランチ上のワークフロー定義でしか
   > 発火しない。ブランチで検証している間は手動起動を使うこと。
   >
   > 各検知ワークフローの末尾から `gh workflow run` で起動する方式は採れない。
   > `GITHUB_TOKEN` で起動した `workflow_dispatch` は GitHub の再帰防止により
   > **新しい run を作らない** (エラーにもならず黙って何も起きない)。

---

## テレメトリアーティファクトの命名

各ワークフローは `telemetry-<tool>-<mode>` という名前でテレメトリをアップロードします
(docs/SPEC.md §6)。`falco-live.yml` は matrix 実行のため、GitHub Actions の制約上
同一 run 内で同名のアーティファクトを複数回アップロードできないので、
`telemetry-falco-live-<falco-version>` (例: `telemetry-falco-live-0.39.0`) という形に
`falco-version` を付加しています。この点のみ `<tool>-<mode>` の厳密な形からの実務上の変形です。
`falco-live.yml` の `live-forked` ジョブ (fork-fixed leg) は `telemetry-falco-live-forked-0.44.1`
という名前を使い、`live` ジョブの2本 (`telemetry-falco-live-0.39.0` /
`telemetry-falco-live-0.39.2`) と衝突しないようにしています。

## アーティファクト保持期間について

このリポジトリ自身がアップロードするアーティファクトはすべて `retention-days: 1` を
明示しています (docs/SPEC.md §1-5)。

一方で `falco-actions` (`stop` action の analyze モード) と `cicd-sensor-action` は、
それぞれ `capture` / `hashes` / `cicd-sensor-report.html` / `cicd-sensor-attestation` という
アーティファクトを**それ自身の内部処理として**アップロードします。これらは
このリポジトリのコードではなく元アクション側の実装であり、`retention-days` を
私たちの側から指定できません (元リポジトリは変更しない方針のため)。

この制約への対処として、`falco-analyze.yml` / `sensor-monitor.yml` / `sensor-enforce.yml`
は、必要な情報を自分たち自身のテレメトリアーティファクト (`retention-days: 1`) に
コピーしたうえで、GitHub API (`gh api -X DELETE .../actions/artifacts/<id>`) で
元のアーティファクトを削除します。アップロードから削除までの間、数秒〜数十秒程度
アーティファクト一覧に元のアーティファクトが載る短い時間差が生じます。これは
元アクションを改変できない制約下での緩和策であり、「最初から一切アップロードしない」
とは技術的に同一ではありません。詳細は各ワークフローファイル冒頭のコメントと
[`docs/SAFETY.md`](docs/SAFETY.md) を参照してください。

## `cicd-sensorctl` のインストールについて

上記「セットアップ」の3を参照してください。

## ライセンス / 出典

このリポジトリは falco-actions / cicd-sensor のどちらのコードも変更しません
(読み取り専用で参照するのみ)。各ツールのライセンス・利用条件はそれぞれの
元リポジトリに従ってください。
