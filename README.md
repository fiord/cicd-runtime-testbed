# cicd-runtime-testbed

`cicd-sensor` と `falco-actions` を GitHub-hosted runner 上で動かし、実際の
検知内容、取得される証跡、証跡からの情報露出、および起動・終了時の異常を
観測するための検証用リポジトリです。production ワークフローへそのまま組み
込むものではありません。

## 先に読むもの

- [調査記録](docs/INVESTIGATION.md) — 実コード、run の実測、結論、未解決点。
- [セットアップ](docs/SETUP.md) — 偽 secret、action pin、バージョン整合性。
- [テスト計画](docs/TEST-PLAN.md) — 次回以降の確認順序と判定観点。
- [仕様](docs/SPEC.md) — カナリアと証跡の期待値。
- [安全上の注意](docs/SAFETY.md) — 実行前に確認すべき権限・公開範囲。
- [既知の修正事項](docs/REQUIRED-FIXES.md) — 発見済みの設計・実装上の問題。

調査の結論はドキュメントの説明ではなく、ワークフロー、シナリオ、取得済み
アーティファクトの実データを優先して更新します。

## 実行するワークフロー

すべて `workflow_dispatch` のみで起動します。

| workflow | 内容 | 正常とみなす条件 |
| --- | --- | --- |
| `falco-live.yml` | upstream Falco 2 leg と fork 修正版 1 leg の比較 | ジョブの緑ではなく、ルールのロード・イベント・起動ログを確認する |
| `falco-analyze.yml` | Falco analyze とキャプチャ由来の証跡確認 | 生キャプチャを使う場合は漏洩リスクを承知して実行する |
| `sensor-monitor.yml` | cicd-sensor standalone で scenarios `00`–`07` を実行 | HTML report と attestation の両方が回収される |
| `sensor-enforce.yml` | `terminate` が実際にプロセスを止めるか確認 | `assert` ジョブの成功が正常 |
| `leak-scan.yml` | telemetry のカナリア・トークン形式を走査 | 結果マトリクスを確認する。赤は乖離または走査不成立を意味し得る |

## 安全な使い方

- `CANARY_ENV` に設定するのは `canaries/canaries.env` と同じ **偽値**だけです。
  本物の secret は登録・注入しません。
- `falco-live.yml` は host の syscall を観測するため、Falco コンテナが runner
  のプロセス、コマンドライン、パスなどを読める前提で動きます。テレメトリを
  public repository で公開可能な情報として扱ってください。
- 現在の `sensor-monitor.yml` はコミット済み設定の `monitor_mode: false` を
  使います。通常のシナリオは kill marker を書きませんが、将来シナリオが
  baseline の terminate 条件に触れればプロセス停止が起こり得ます。
- `live-forked` は調査中の `fiord/falco-actions` ブランチを参照しています。
  安定後は必ず commit SHA に pin してください。

## 証跡の扱い

このリポジトリが再アップロードする telemetry artifact は、現行コードでは
`retention-days: 7` です。元 action が作る artifact は回収後に削除を試みますが、
アップロードから削除までの短時間は閲覧可能です。生の `capture.scap` を扱う
`falco-analyze.yml` は特に注意してください。

詳細な証跡形式、カナリアごとの期待値、過去の障害経緯は `docs/` に置きます。
