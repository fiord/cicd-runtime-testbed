# GitHub Actions の CI/CD ランタイム検知: Falco と cicd-sensor

対象読者は、依存関係の改ざん、資格情報の読取り、外部通信、workflow ファイルの
書換えなど、CI/CD におけるサプライチェーン攻撃を検知し、必要なら影響を抑えたい
エンジニアである。本書は testbed で実行した GitHub-hosted runner の結果に基づく。
以降の「私の検証環境では」は、この testbed で得た実測であり、他の runner や rule
でも同じ結果を保証するものではない。一般化できない箇所は明記する。実行記録の詳細は
[docs/INVESTIGATION.md](docs/INVESTIGATION.md) を参照する。

## まず押さえる用語と観測できる範囲

GitHub Actions の **workflow** は YAML で書く自動処理であり、各 **job** は通常、
一時的な Linux 仮想マシン（**runner**）で実行される。Falco/cicd-sensor は、この
runner 上で動く process やファイル操作、通信を観察する security action である。

```text
workflow 開始 → runner 作成 → checkout → security action を起動
                                      ↓
                           以後の build/test/deploy を観測
                                      ↓
                           post step で artifact を保存
```

この順序が重要である。security action を起動する**前**の checkout や setup で起きた
挙動は、原則として観測できない。また runner は job 終了後に破棄されるため、調査用の
データは **artifact**（Actions に保存するファイル）として明示的に残さなければ失われる。

- **rule（ルール）**: 「どの行為を不審とみなすか」を表す条件。例: 特定の workflow
  ファイルへの書込み、秘密情報らしい値を含む argv、未知の外部通信。
- **event（イベント）**: rule 判定の材料となる実行記録。Falco/cicd-sensor は OS が
  process 実行・file open・network 接続等を行う際の情報を利用する。こうした OS への
  低レベル操作を syscall（system call）という。
- **eBPF**: Linux kernel の event を比較的低い粒度で取得する仕組み。便利だが、通常の
  application log より runner の権限・kernel・性能への依存が大きい。
- **post step**: Actions の通常 step が終わった後にも action が実行する後処理。report
  upload はここで行われるため、process を terminate すると後処理が途中で欠ける場合がある。

### Falco の二つの mode

- **live mode**: Falco を先に起動し、その後に続く build/test 等をリアルタイムに監視する。
  ルールに一致した event をその場で JSON/log に記録する。runtime を止める機能は持たない。
- **analyze mode**: 別 job で syscall の記録（**capture**）を取り、後続 job でそのファイルを
  replay して解析する。抽出条件を変えて再調査しやすい一方、capture は情報量が大きい。

### cicd-sensor の `monitor_mode`

cicd-sensor は config と rule の action を組み合わせる。本 testbed では
`monitor_mode: true` を観測中心、`false` を `terminate` を許可する enforcement 側として
扱う。名前だけで安全性を判断せず、実際に rule hit の `action` と `result` を report で
確認することが必要である。

## 先に結論

- **Falco** は syscall/capture から低レベルの行動を広く採取し、後追い解析する。
  調査能力は高いが、privileged container、host mount、artifact と image/action の
  固定を許容・設計できるチーム向けである。単体ではブロックしない。
- **cicd-sensor** は CI/CD 用ルールを agent が評価し、HTML report と attestation を
  出す。ルールに `terminate` を指定すれば対象 process を止められる。導入面は
  Falco より単純だが、report の情報量、ルール互換性、terminate 後の証跡欠落を
  運用で扱う必要がある。
- どちらも「secret を漏らさない」製品ではない。取得した artifact 自体が新しい
  情報資産になるため、private repository、最小権限、保持期間、外部連携を先に決める。

## どう動き、何を取得するか

| | Falco | cicd-sensor |
| --- | --- | --- |
| 実行方式 | live mode は Falco コンテナを起動して runtime event を記録。analyze mode は syscall capture を別 job で replay | GitHub Action が agent を起動し、実行中の event を CI/CD ルールで評価。post step が report/attestation を生成 |
| 主な設定場所 | workflow の action 入力、Falco rule YAML | `.cicd-sensor/config.yaml`、`.cicd-sensor/rules/*.yaml`、workflow の action 入力 |
| 主な成果物 | Falco event JSON、起動/停止ログ、process、書込み path、DNS、接続先、hash、container、必要なら raw `capture.scap` | HTML report、証跡用 JSON (`predicate.json`)、rule hit、action/result、CI/CD メタデータ |
| ブロック | action 単体は記録・報告。job を失敗させる gate は workflow 側で明示的に実装する | `action: terminate` で一致した process を停止できる。ネットワーク遮断や runner 全体の隔離を保証するものではない |

### Falco の実行方式と取得例

GitHub Actions で Falco を使うときは、通常 `falco-actions` のような action wrapper が
Docker で Falco を起動する。live mode の action は `docker run --privileged` で Falco を
起動し、`/tmp`、Docker socket、host の `/proc` と `/etc` を mount する。modern eBPF
engine が runtime event を読み、rule に一致した event を JSON に書く。analyze mode は
sysdig capture を取り、Falco replay と複数の抽出処理を行う。

ここで `--privileged` は container に強い host 側の権限を与える指定、mount は runner の
path を container から読めるようにする指定である。Falco の観測には必要な場合があるが、
通常の build action より高い権限を渡すことになる。

私の検証環境では、**Falco v0.44.1** が
`/etc/falco/rules.d/cicd_rules.yaml` を実際にロードし、`Source Code Overwrite` を
8件記録した。4件は `package.json` / `package-lock.json` / 無効化済み workflow への
書込みという scenario、4件は GitHub Actions が job を管理するために行う runner 自身の
`$GITHUB_ENV` / step-summary 書込みだった。例えば、次のような event が得られた
（path の一部は省略）。

```text
rule:    Source Code Overwrite
file:    .../cicd-runtime-testbed/package.json
process: npm (executable: /usr/local/bin/node)
parent:  bash → Runner.Worker → Runner.Listener
```

このように Falco event は「rule が発火して初めて」詳細が出る。導入後は、
package manager や runner 自身を攻撃と誤認しないよう、除外条件を rule に追加・調整する
作業が必要である。

私の検証環境では analyze mode で event drop 0・4イベントを確認し、次の
加工済み telemetry を GitHub Actions の artifact として受け取った。

| artifact 内のファイル | 何が入るか | 実測で見えた例 |
| --- | --- | --- |
| `proc.txt` | process 名、実行 path、親 process | runner が起動した command と executable path |
| `files_written.txt` | 書込み path、process、親 process | `package.json` を `npm` が書いた記録 |
| `outbound.txt` / `top_connection.txt` | 接続先 IP/port、process/executable | Cloudflare 宛先、Azure resolver/IMDS、通信した process |
| `dns_extract_json.txt` | DNS 問合せ | scenario が問い合わせた domain |
| `hashes.txt` | executable path と SHA-256 | runner 上で実行されたバイナリの hash |
| `containers.txt` / `udp_extract.txt` / `topprocs_net.txt` | container、UDP、通信量上位 | 空の場合もある。今回の container/UDP は空だった |
| `forked-analyze-outcome.md` | replay 成否と rule 読込み確認 | CI/CD rule がロードされ replay が成功したという記録 |

raw `capture.scap` も取得できるが、既定では再アップロードしない。今回、action が
一時 upload した capture は約1.8 MB、加工済み telemetry は約12 KBだった。raw capture
は後追い解析の価値が最も高い一方、syscall buffer を含み得るため最も高リスクである。

### cicd-sensor の実行方式と取得例

cicd-sensor-action は agent を起動し、呼出元 repository の `GITHUB_SHA` にある
`.cicd-sensor/config.yaml` と rules を GitHub Contents API から読む。したがって、
workflow 中に workspace の config を書き換えても agent 設定には反映されない。

post step は次を artifact として出す。

- **HTML report**: 全 rule hit の上位集合。rule ID、`detect`/`terminate` 等の action、
  result、event に由来する argv・path・DNS・URL 等を含み得る
- **attestation predicate**: provenance（由来を記録する）用途にも使える `predicate.json`。
  detect/terminate hit と project path、
  commit SHA、actor、runner tracking ID、job/run link、接続先 IP/domain 等を含む
- 任意の debug bundle: runtime event log、journal、raw result-log、systemd snapshot
  を含むため、通常は無効にする

私の検証環境では rule validation が成功し、67 rules・warning 0・`http_request` の
実 hit を確認した。HTML report と predicate を回収でき、report には短い argv、DNS、
ファイル path、URL path の偽カナリアが現れた。実際の HTML は、次のように rule と
process 情報を組み合わせた JSON を埋め込む（値を伏せた例は
[examples/cicd-sensor-report-sanitized.html](examples/cicd-sensor-report-sanitized.html)）。

```json
{
  "rule_id": "testbed_canary_argv_carrier",
  "event_type": "process_exec",
  "action": "collect",
  "process": {
    "exec_path": "/usr/bin/curl",
    "argv": ["curl", "--referer", "CNRY..."],
    "ancestors": ["bash", "Runner.Worker"]
  }
}
```

私の検証環境では、kill marker を書いた process が exit 130 で止まり、report の
`testbed_kill_marker` は `action: terminate` / `result: terminated` だった。これは
検知だけでなく、ルールに基づく process 停止が動作した実測である。

## 秘匿情報・外部送信のリスク

artifact は Actions 権限を持つ人が取得できる。今回の値は偽カナリアだったが、以下は
実際に観測された、またはコード上可能な露出である。

| 経路 | Falco | cicd-sensor |
| --- | --- | --- |
| artifact 内の情報 | runner の接続先、Azure resolver/IMDS、executable path、書込み path、DNS。raw capture を残せばさらに広い syscall 情報 | argv、path、DNS、URL path、rule/action/result、actor・commit・run URL・接続先等 |
| 実測した非検出 | 加工済み telemetry で GitHub token/JWT形式は0件。ただし非露出の保証ではない | report/predicate で ENV、ファイル内容、長い argv、Authorization 値、URL query、token/JWT形式は0件。ただし非露出の保証ではない |
| 任意の外部送信 | `VT_API_KEY` を渡すと IP/hash を VirusTotal に照会。`OPENAI_API_KEY` を渡すと report 全体を OpenAI API へ要約依頼 | manager URL を設定すると設定取得先が manager になる。debug artifact を有効にすると収集量が増える |

HTML report を公開用に確認したところ、既知の GitHub token/JWT/Authorization/private-key
形式は検出されなかった。しかし 23件の rule hit、actor・commit・runner tracking ID、
argv/path を含んでいた。これは調査には有益だが、恒久的に repository へ置く生データには
向かない。そこで生 HTML は commit せず、構造だけを示すサニタイズ済み HTML を
`examples/` に置く。実際の report は短期 artifact として限定した閲覧者にだけ公開する。

さらに analyze mode の stop action は raw `capture` をいったん upload する。既定の
`upload_raw_capture: false` は加工済み telemetry への再アップロードを防ぐだけであり、
後続 job が削除するまでの短時間は raw artifact が存在する。公開 repository や強い
secret を扱う job では、この一時露出も許容できるかを先に判断する。

Falco action は Docker Hub image を pull し、analyze 時に Python dependency を install する。
cicd-sensor action も agent release を取得する。Actions、container image、agent version は
immutable SHA/digest に固定し、release artifact の検証方針も確認すること。特に本 testbed
の Falco 修正版 action は検証中の branch ref を使っており、**本番では commit SHA に固定するまで
推奨しない**。

## リソース負荷と実行時間

今回の GitHub-hosted runner では job の壁時計時間だけを測った。CPU、メモリ、disk I/O、
network bytes は測っていないため、「負荷が軽い」とは結論づけられない。

| 実測 | 壁時計時間 | 解釈 |
| --- | ---: | --- |
| Falco live 3 legs | 各24–30秒 | image の取得状況・短い scenario を含む。修正版 action は event を取得 |
| Falco analyze | capture 33秒 + replay 40秒 | capture/upload/download、replay、抽出、dependency install を含む |
| cicd-sensor monitor | agent/scenario 17秒 + 回収5秒 | rule validation、agent 起動、report/attestation upload を含む |
| cicd-sensor enforce | kill job 14秒 + assert/回収11秒 | terminate により scenario は意図的に失敗 |

Falco live の privileged eBPF container と capture は、特に self-hosted runner では負荷と
権限の両面で大きい。cicd-sensor も eBPF agent を使うためゼロコストではない。導入前に
代表的な job で、基準 run と導入 run の wall time、CPU、メモリ使用量（RSS）、disk、artifact サイズを
比較する検証を行うべきである。

## 設定の容易さとカスタマイズ性

### Falco

workflow に start/stop（または analyze）action、Falco image/version、rule を指定する。
`custom-rule-file`、`cicd-rules`、image/version、process/DNS/connection/hash 等の抽出を
選べるためカスタマイズ性は高い。一方、container の権限・mount・artifact cleanup・
失敗時の gate を workflow 側で設計する必要がある。

次は testbed の構成を短縮した live mode の例である。security action は、観測したい
step より前に置く。`<...>` は production では検証済みの固定 commit SHA / image digest
（内容ハッシュ）に置き換える。

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@<commit-sha>
  - name: Start Falco before the build
    uses: <falco-actions>/start@<commit-sha>
    with:
      mode: live
      falco-image: falcosecurity/falco
      falco-version: "0.44.1" # production では digest も検討
      cicd-rules: true
  - run: npm ci && npm test             # この step 以後を観測する
  - name: Stop Falco
    if: always()
    uses: <falco-actions>/stop@<commit-sha>
    with:
      mode: live
  - name: Save evidence
    if: always()
    uses: actions/upload-artifact@<commit-sha>
    with:
      name: telemetry-falco
      path: telemetry/
      retention-days: 7
```

この YAML だけでは block にならない。`falco_events.json` を読み、重大 rule があれば
`exit 1` にして workflow を失敗させる step を後段に置いて初めて、後続 deploy 等を止める
gate になる。ただし、その時点では該当 process が既に実行された後である。

現状の重要な注意点は、upstream falco-actions の CI/CD rule mount path に問題があり、
コンテナが起動しても custom rule がロードされず、緑の job が「何も検知していない」
状態になり得ることである。本 testbed は fork で修正し、`Loading rules from:` に
`cicd_rules.yaml` があることを明示的に確認している。Falco の導入では、起動成功だけを
成功条件にせず、対象 rule file のロードと少なくとも1つの既知 event を確認する。

### cicd-sensor

workflow に pinned action と `contents: read` を置き、repository に config/rule YAML を
コミットする構成で始められる。検知ルール、`monitor_mode`、manager URL、socket、HTML /
attestation / debug artifact の有無を調整できる。設定をコードレビューできる点は CI/CD
への導入に向く。

次は testbed と同じ「agent job と回収 job を分ける」構成を短縮した例である。HTML と
attestation の upload は action の post step が行う。後段 job はそれを download し、
保持期間を決めた telemetry artifact に詰め直す。

```yaml
permissions: {}
jobs:
  monitor:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@<commit-sha>
      - name: Start the eBPF sensor
        uses: cicd-sensor/cicd-sensor-action@<commit-sha>
        with:
          cicd-sensor-version: v0.0.46
          enable-html-report: true
          enable-attestation-artifact: true
      - run: npm ci && npm test
  collect:
    needs: monitor
    permissions:
      actions: write # 元 artifact の回収・削除を行う場合だけ必要
    steps:
      - uses: actions/download-artifact@<commit-sha>
        with:
          name: cicd-sensor-report.html
          path: telemetry/cicd-sensor-report
      - uses: actions/upload-artifact@<commit-sha>
        with:
          name: telemetry-cicd-sensor
          path: telemetry/
          retention-days: 7
```

ただし rule の event type が agent version と合わないと、project config bundle 全体が
無効になり得る。workflow 内で agent と validator の version を揃え、事前 validation を
必須にする。`terminate` を有効にする場合は、対象 rule を最小化し、専用の enforce test を
継続する。今回も terminate 後に attestation upload が finalize されず、HTML report だけが
回収された。report を一次証跡、attestation を補助証跡として扱う必要がある。

## 現時点で実用的か

**段階導入なら両方とも実用的である。** ただし、最初から本番の blocker として全面適用
するのではなく、次の順で進めることを推奨する。

1. まず detect-only 相当で artifact と誤検知を確認し、secret を含む job では artifact
   の閲覧者・保持期間を絞る。
2. Falco は action/image/rule を SHA/digest へ固定し、rule path と event を CI で assert
   する。raw capture は事故調査時だけ、短期保持・限定アクセスで有効化する。
3. cicd-sensor は config/rule validation と HTML report 回収を成功条件にする。terminate
   は kill 専用 rule から始め、開発ツール・package manager への誤検知を測る。
4. 自組織の runner・依存関係・secrets を使った負荷測定、漏洩走査、失敗時の fail-open /
   fail-closed 方針を決めてから block を広げる。

この testbed で有効性を確認できたのは、あくまで定義済み scenario と GitHub-hosted runner
上の挙動である。未知の攻撃を包括的に防ぐ保証ではなく、ルール・artifact 運用・他の
予防策（least privilege、dependency pinning、egress 制御、review）と組み合わせる
検知/対応の一層として評価する。
