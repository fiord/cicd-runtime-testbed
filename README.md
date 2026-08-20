# cicd-runtime-testbed

`falcosecurity/falco-actions` と `cicd-sensor` を実際に GitHub Actions 上で動かし、

- **T1**: 検知が行なわれるか。cicd-sensor では、実際にプロセス kill が起きるか
- **T2**: 実際にどのような情報が取得・閲覧できるか
- **T3**: public repo で動かした際に secret 情報が漏れないか

の3点を実地で確認するためのテスト用リポジトリです。

**このリポジトリは検証用です。production ワークフローにそのまま組み込むものではありません。**
詳しい設計契約は [`docs/SPEC.md`](docs/SPEC.md) を、安全上の注意点は [`docs/SAFETY.md`](docs/SAFETY.md) を参照してください。

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

### 3. `cicd-sensorctl` の入手経路について (未検証)

`sensor-monitor.yml` / `sensor-enforce.yml` は `cicd-sensorctl rule validate` を実行する前に、
`cicd-sensor/docs/user-guide/self-hosted-install.md` に記載の命名規則
(`cicd-sensor_<version>_linux_<arch>.tar.gz` に `cicd-sensorctl-linux-<arch>` が入っている)
から構成した URL パターンで `gh release download v0.0.38 --repo cicd-sensor/cicd-sensor` を
実行します。

**この方法は実際のリリース一覧に対して検証できていません。** `cicd-sensor/cicd-sensor` の
公開 API を確認したところ `v0.0.38` タグの release が見つからず (404)、この時点では
リポジトリが private である可能性、まだ該当バージョンの release が無い可能性、
命名規則が異なる可能性のいずれも排除できていません。実行前に必ず:

```sh
gh release list --repo cicd-sensor/cicd-sensor
gh release view v0.0.38 --repo cicd-sensor/cicd-sensor
```

などで実際のリリース資産名・バージョンを確認し、ワークフロー内の該当ステップ
(`Install cicd-sensorctl`) を実際の値に合わせて修正してください。`cicd-sensor/cicd-sensor`
が private repo の場合は、`GH_TOKEN` を読み取り権限のある PAT に差し替える必要があります
(`github.token` は実行中のリポジトリにしかアクセスできません)。

このステップが失敗しても後続の `cicd-sensor-action` 自体は動きます (rule validate が
スキップされ、警告が出るだけです)。

---

## ワークフロー一覧

| ワークフロー | 目的 | 実行方法 | 期待される結果 |
| --- | --- | --- | --- |
| `falco-live.yml` | falco live モードでの検知 (`falco-version` 0.39.0 / 0.43.0 の matrix) | Actions タブから workflow_dispatch で実行 (入力なし) | 各バージョンの `telemetry-falco-live-<version>` アーティファクトに job summary と (取得できれば) `falco_events.json` が入る。0.39.0 側で `required_engine_version: 0.43.0` との不整合が実際に何を起こすか (起動失敗/警告のみ/黙って通る等) を job summary の "matrix note" セクションで確認する |
| `falco-analyze.yml` | falco analyze モードでの検知と生キャプチャ | workflow_dispatch。`upload_raw_capture` (既定 false) で生キャプチャの取り扱いを制御 | `telemetry-falco-analyze` アーティファクトに job summary・抽出情報 (processes/connections/dns/containers/written-files/hashes) が入る。`upload_raw_capture: true` のときのみ `capture.scap` も含む |
| `sensor-monitor.yml` | cicd-sensor の検知 (kill なし、`monitor_mode: true`) | workflow_dispatch (入力なし) | 全シナリオ (00〜07。07 は detect / collect ルール専用) が実行され、`telemetry-cicd-sensor-monitor` に HTML レポートと attestation predicate が入る |
| `sensor-enforce.yml` | cicd-sensor の kill 動作の検証。**成功が正常** | workflow_dispatch (入力なし) | `assert` ジョブが **成功** すれば kill が確認できたことを意味する。失敗した場合は kill が起きなかったことを意味し、要調査 |
| `leak-scan.yml` | 漏洩マトリクスの生成 (T3) | workflow_dispatch。`run_id` に上記いずれかのワークフロー実行の run ID を入力 | 対象 run の `telemetry-*` アーティファクトを横断的に走査し、job summary にカナリアごとの 期待 vs 実測 のマトリクスを出す。⚠️ が1つでもあれば非ゼロ終了する (仮説と現実が食い違ったことを目立たせるため。この場合の赤は「異常」ではなく「注目すべき結果」) |

### 推奨実行順序

1. `sensor-monitor.yml` と `falco-live.yml` / `falco-analyze.yml` を先に実行し、検知結果とテレメトリを集める (T1 前半 / T2)。
2. `sensor-enforce.yml` を実行し、kill が実際に起きることを確認する (T1 後半)。
3. 1 で得た run_id を使って `leak-scan.yml` を実行し、T3 を確認する。

---

## テレメトリアーティファクトの命名

各ワークフローは `telemetry-<tool>-<mode>` という名前でテレメトリをアップロードします
(docs/SPEC.md §6)。`falco-live.yml` は matrix 実行のため、GitHub Actions の制約上
同一 run 内で同名のアーティファクトを複数回アップロードできないので、
`telemetry-falco-live-<falco-version>` (例: `telemetry-falco-live-0.39.0`) という形に
`falco-version` を付加しています。この点のみ `<tool>-<mode>` の厳密な形からの実務上の変形です。

## アーティファクト保持期間について

このリポジトリ自身がアップロードするアーティファクトはすべて `retention-days: 1` を
明示しています (docs/SPEC.md §1-5)。

一方で `falco-actions` (`stop` action の analyze モード) と `cicd-sensor-action` は、
それぞれ `capture` / `hashes` / `cicd-sensor-report` / `cicd-sensor-attestation` という
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

上記「セットアップ」の3を参照してください。未検証の推定です。

## ライセンス / 出典

このリポジトリは falco-actions / cicd-sensor のどちらのコードも変更しません
(読み取り専用で参照するのみ)。各ツールのライセンス・利用条件はそれぞれの
元リポジトリに従ってください。
