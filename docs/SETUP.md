# セットアップ

実行前に、次の3点だけを確認する。詳細な実行順と判定は
[TEST-PLAN.md](TEST-PLAN.md)、実測済みの挙動は
[INVESTIGATION.md](INVESTIGATION.md) を参照する。

## 1. 偽の `CANARY_ENV` を登録する

リポジトリの Actions secret `CANARY_ENV` に、`canaries/canaries.env` にある
`CANARY_ENV` と**同じ偽値**を登録する。本物の token、API key、認証情報を
登録してはならない。未登録でも workflow は動くが、環境変数経由の露出検証は
成立しない。

## 2. action の参照を確認する

- upstream Falco action は `falcosecurity/falco-actions` の commit
  `558a3ceeee9403e1c875ffbeb704c34c93e24752` に pin されている。
- cicd-sensor action は commit
  `6511eb44c91d71b2b93d71193b1bf2cb18352f66` (`v0.0.38`) に pin されている。
- `live-forked` と `falco-analyze.yml` の fork actions は
  `fiord/falco-actions@fix/cicd-rules-mount-path` を参照する。調査中の
  意図的な branch 参照である。結果が安定したら commit SHA に戻す。

参照先を更新する場合は、参照する action の実ファイルと Docker image の対応を
確認してから、commit SHA と調査記録を同時に更新する。

## 3. cicd-sensor の agent と validator を揃える

`sensor-monitor.yml` と `sensor-enforce.yml` の `CICD_SENSOR_VERSION` を、
validator の download と `cicd-sensor-action` の入力で同一に保つ。現行値は
`v0.0.46` で、release tag は `releases/v0.0.46` 形式である。

`http_request` を使う custom rule はこのバージョンを必要とする。下げる場合は
該当 rule も外す。無効な rule が1本でもあると、action 側で config bundle 全体が
破棄され、`monitor_mode` を含む project 設定が適用されない。

## 実行時の注意

すべて手動起動である。`sensor-enforce.yml` は `assert` の成功が kill 確認を
意味する。`falco-live.yml` の成功は検知成功を意味しないため、artifact と起動
ログを確認する。raw `capture.scap` を含める `falco-analyze.yml` は、公開可能な
偽値だけで実行する。
