# 実行実態と調査記録

最終確認: 2026-08-31 (JST)。この文書は、説明文ではなくワークフロー・
シナリオ・アーティファクトを読んだ結果を簡潔に記録する。

## 根拠と対象

- 対象 run: [falco-live 33311769634](https://github.com/fiord/cicd-runtime-testbed/actions/runs/33311769634)、[sensor-monitor 33311807928](https://github.com/fiord/cicd-runtime-testbed/actions/runs/33311807928)。
- どちらも `workflow_dispatch`、コミット SHA は `7cbe678195aa2f53a7b9543ea33d000fcf0149d2`。
- ローカル `HEAD` も同じ SHA。`falco-live.yml` の未コミット 394 行の追記は
  この run の**後**に加えられたもので、実測の根拠には含めない。
- `gh run view` でジョブ・ステップを確認し、`gh run download` で telemetry
  artifact を展開した。カナリア比較には `tools/scan-leaks.sh` を使った。

## 実際に行うこと

### 共通シナリオ

`scenarios/00`–`07` は、偽の AWS/Docker/npm 資格情報の作成・読取り、自己
環境の読取り、予約ドメインへの DNS/HTTP 要求、ローカル package の
`postinstall`、無効化済み workflow ファイルの作成、無害な memfd 実行、
作成物の削除、カスタム rule marker の書込みを行う。外部に送る先は
`example.com` と `*.test.invalid` であり、npm registry から依存関係を取得
しない。`90-killme.sh` はこの一覧と別で、`sensor-enforce.yml` 専用である。

### `falco-live.yml`

実コードは `live` と `live-forked` の3 legを実行する。

| leg | action / engine | 権限 | 収集物 |
| --- | --- | --- | --- |
| upstream | `falcosecurity/falco-actions` の SHA pin、`falco-no-driver` 0.39.0 / 0.39.2 | `contents: read`, `actions: read` | 起動・停止・ストリームログ、イベント、docker events、シナリオ log |
| fork | `fiord/falco-actions@fix/cicd-rules-mount-path`、`falcosecurity/falco` 0.44.1 | 同上 | 同上 |

各 leg は Docker Hub tag を preflight した後、Falco を live mode で起動し、
`docker logs -f` と `docker events` をバックグラウンド保存してからシナリオを
実行する。起動 action は `continue-on-error: true` のため、ジョブが緑でも
起動・検知成功を意味しない。停止時の `--rm` により終了コードは取得不能な
場合があり、ストリームログと docker event が異常確認の主根拠になる。

### `sensor-monitor.yml`

`ubuntu-24.04` で `cicd-sensorctl` と agent の両方を `v0.0.46` に揃え、
`.cicd-sensor/rules` を検証してから standalone action を起動する。
monitor job の権限は `contents: read`。後続の telemetry job は元 artifact を
削除するため `actions: write` も持つ。

重要なのは、action が config と custom rules をワークスペースからではなく
`GITHUB_SHA` の GitHub Contents API から取る点である。従って実行中に
`config.yaml` を書き換えても無効で、今回実際に使われた
`monitor_mode` はコミット済みの `false`。この workflow は kill marker を
書かないが、将来 baseline の terminate rule に触れるシナリオを加えると
プロセスを止める可能性がある。

report HTML と attestation predicate を download し、両方を
`telemetry-cicd-sensor-monitor` に再アップロードする。1件も回収できなければ
収集 job を失敗させ、元 artifact は削除を試みる。

## 実測結果

### Falco live — run 33311769634

run と全3 job は success だったが、判定は次のとおり。

| leg | 実測 | 判定 |
| --- | --- | --- |
| upstream 0.39.0 | Falco 0.39.0 は起動。`cicd_rules.yaml` のロード記録なし、`falco_events.json` なし | 検知が動いた証拠なし |
| upstream 0.39.2 | Falco 0.39.2 は起動。`cicd_rules.yaml` のロード記録なし、`falco_events.json` なし | 同上 |
| fork 0.44.1 | Falco 0.44.1 は起動し、`/etc/falco/rules.d/cicd_rules.yaml` をロード。イベント8件を保存 | CI/CD rule のマウント修正は有効 |

fork の8件には runner の `_runner_file_commands` への `$GITHUB_ENV` /
`$GITHUB_STEP_SUMMARY` 書込み、`package.json`・`package-lock.json`、無効化済み
workflow ファイルへの書込みが含まれる。少なくとも一部はハーネス自身による
`Source Code Overwrite` であり、シナリオ固有の悪性挙動だけではない。

fork の起動ログには、いくつかの TOCTOU mitigation 用 tracepoint を attach
できない警告がある。ただし「検知は継続する」と記録され、コンテナの crash や
`die` event は得られなかった。`--rm` のため終了コードは未取得であり、
「正常終了を完全に証明できた」わけではない。upstream の緑は、起動 action の
失敗が許容され、CI/CD rule を読み込めなくても失敗させない設計によるので、
検知成功の指標にしてはいけない。

展開した live telemetry に対するカナリア走査では、upstream 0.39.2 と fork
でカナリア値・GitHub token形式・JWT形式は検出されなかった。ただしこれは
live telemetry に生キャプチャが無く、fork のイベントが主に file write に
限られた今回の観測結果であって、Falco 一般が secret を出力しない証明ではない。

### cicd-sensor monitor — run 33311807928

monitor と telemetry collection は success。rule validation も成功し、
report HTML と predicate の2 artifact が揃った。predicate は `detected` を
記録し、次の detect rule を各1回記録した。

- `testbed_detect_marker`
- `anchored_multi_family_credential_access` (baseline)

HTML report の解析では 67 rules、warnings 0、`http_request` 対応あり。カナリア
走査では `CANARY_ARGV_SHORT`、`CANARY_DNS`、`CANARY_PATH`、
`CANARY_URL_PATH` が report（DNS は predicate にも）に現れた。一方
`CANARY_ENV`、`CANARY_FILE`、`CANARY_ARGV_FLAG`、`CANARY_ARGV_LONG`、
`CANARY_URL_QUERY`、GitHub token形式、JWT形式は検出されなかった。

これは少なくとも、HTML report が argv・パス・URL path・DNS を公開することを
示す。いずれも今回の値は偽カナリアだが、本物の値を同じ経路に載せれば artifact
へ出る前提で扱う必要がある。predicate には project path、commit SHA、actor、
runner tracking ID、job/run link、接続先 IP と domain も含まれる。

## 現時点の結論と次の確認

- fork の mount-path 修正は実測で CI/CD rules のロードまで回復させた。
  upstream 2 leg は緑でも検知データを生成していない。
- cicd-sensor は検知・report/attestation 回収まで動作した。ただし standalone
  の predicate は集計であり、HTML report の露出範囲を別途確認する必要がある。
- 今回は runner token の形式検出が0件だった。しかし `falco-analyze.yml` の
  raw `capture.scap` は別のリスク面であり、この2 run は安全性の証明にならない。
- 現行 workflow が再アップロードする telemetry の保持期間はコード上7日。
  raw `capture.scap` を含む `telemetry-falco-analyze` だけは1日である。
- 次回 Falco run では、シナリオ後に drain window を置き、イベントの遅延と
  真の未検知を分ける。終了コードが必要なら `--rm` を使わない観測モードを
  別途設ける。
