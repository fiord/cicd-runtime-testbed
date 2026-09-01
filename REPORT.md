# GitHub Actions 上の CI/CD ランタイム検知 調査レポート

最終確認: 2026-09-01 (JST)。本レポートは testbed での実行結果に限る。詳細な
run と artifact の根拠は [docs/INVESTIGATION.md](docs/INVESTIGATION.md) を参照する。

## 結論

Falco と cicd-sensor はともに、GitHub-hosted runner 上で「何が実行・書込み・
通信されたか」を記録し、ルールに一致した挙動を検知できた。ただし、どちらも
secret の非露出を保証する製品ではない。出力・artifact の公開範囲、保持期間、
ルールの読み込み確認を運用に組み込む必要がある。

| 観点 | Falco | cicd-sensor |
| --- | --- | --- |
| 主な役割 | syscall/capture を基にした runtime 検知・再解析 | CI/CD 向けルール評価、report/attestation、必要時の process terminate |
| 実測済み | CI/CD rules のロード、source-code overwrite、DNS・書込み・process 等の抽出 | file/process/HTTP/DNS 系の rule hit、HTML report、attestation、kill rule |
| 実用性 | fork 修正版とルール読み込み検証を前提に有用 | 検知・証跡収集は実用的。terminate は専用テストで継続確認が必要 |

## Falco で取得できるもの

live mode では Falco の起動・停止ログ、イベント JSON、Docker event、シナリオ log
を回収する。fork 修正版を使った run `33460618900` では、
`/etc/falco/rules.d/cicd_rules.yaml` がロードされ、`Source Code Overwrite` を
8件取得した。内訳は scenario による `package.json`、`package-lock.json`、
無効化済み workflow の書込み4件と、runner 自身の file-command 書込み4件である。
したがって、イベントには test harness 由来のノイズも含まれる。

analyze mode は一度取得した syscall capture を別 job で replay し、次の加工済み
telemetry を作る。

- 実行 process と executable path
- 書込みファイルの path
- outbound connection、DNS、UDP、top connection
- executable hash、container 情報、Falco rule hit

run `33346627573` では replay が event drop 0・4イベントで成功し、上記の抽出
telemetry 9種を回収した。raw `capture.scap` は既定では再アップロードしないが、
必要に応じて残す設定は可能である。これは syscall buffer を含み得るため、もっとも
慎重に扱うべき成果物である。

## cicd-sensor で取得できるもの

cicd-sensor は standalone action が HTML report と attestation predicate を出す。
HTML report は hit の上位集合で、rule ID、action、result、関連する event 情報を
含む。predicate には detect/terminate の hit に加え、project path、commit SHA、
actor、runner tracking ID、job/run link、接続先 IP/domain が残る。

run `33460651460` では67 rules・warning 0・`http_request` の実ヒットを確認した。
leak-scan では、短い argv、DNS、ファイル path、URL path の偽カナリアが report
へ現れた一方、環境変数、ファイル内容、長い argv、Authorization 値、URL query、
GitHub token/JWT形式は検出されなかった。

run `33460630300` の enforce では、kill marker を書いた process が exit 130 で停止し、
report の `testbed_kill_marker` は `action: terminate` / `result: terminated` だった。
つまり検知だけでなく、ルールに基づくプロセス停止も実証できている。

## できること・できないこと

両者で、ルールに明示した挙動の可視化、証跡 artifact の保存、後追い調査ができる。
cicd-sensor は terminate、Falco analyze は capture の後追い抽出がそれぞれ固有の
強みである。

一方で、次は保証できない。

- ルールに無い挙動の自動検知、または検知結果だけでの侵害判定
- artifact に secret が残らないこと。今回も Falco telemetry には runner の network
  endpoint と executable path、cicd-sensor report には argv/path 等が現れた
- コンテナ起動成功だけからのルール有効性。Falco は対象 rule file が実際に
  `Loading rules from:` に出たことを確認する必要がある
- cicd-sensor の設定を runtime に書き換えて反映すること。action は config/rules を
  `GITHUB_SHA` の GitHub Contents API から取得する
- enforce 時の attestation 完全性。process terminate により action の post-step が
  中断し、attestation upload が欠けることがある。HTML report を一次証跡にする

## 現段階の実用性

**Falco は条件付きで実用的**である。fork 修正版と `falcosecurity/falco:0.44.1` では
CI/CD rules のロードと検知を確認できた。ただし upstream 0.39.x では同 rule を
ロードせずイベントも出なかった。起動後に rule path、イベント数、harness ノイズを
確認し、raw capture を通常は保存しない運用が必要である。

**cicd-sensor は CI/CD 向けの検知・証跡収集として実用的**である。現行設定で
validation、report、attestation、leak-scan、terminate を確認できた。ただし custom
rule の互換性失敗は設定 bundle 全体を無効化し得るため、事前 validation と HTML
report の確認を必須にする。terminate を使う場合は、report 回収を成功条件に含め、
attestation は best-effort と扱うのが妥当である。
