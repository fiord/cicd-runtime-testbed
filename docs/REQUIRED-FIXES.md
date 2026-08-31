# 本質的なテストを成立させるために必要な修正

## 0. この文書の位置づけ

このリポジトリが本来やりたいことは、`falcosecurity/falco-actions` と
`cicd-sensor/cicd-sensor-action` を **同じ攻撃シナリオに対して公平に走らせ**、
T1 (検知・kill)、T2 (証跡)、T3 (secret 漏洩) を比較することである。

しかし実測結果を見る限り、**現時点では「比較」が成立していない**。
片方 (falco) は事実上ほとんど何も観測できておらず、もう片方 (cicd-sensor) は
観測できているが結果がジョブログに出ないため評価が困難になっている。

この文書は、その gap を埋めるために **upstream (`falco-actions`) 側**と
**本リポジトリ側**にそれぞれ何を直す必要があるかを、実測の根拠付きで列挙する。

### 根拠にした run (すべて各ワークフローの最新)

| ワークフロー | run | 日付 |
|---|---|---|
| falco-live | [32625231129](https://github.com/fiord/cicd-runtime-testbed/actions/runs/32625231129) | 2026-08-23 |
| falco-analyze | [32625240102](https://github.com/fiord/cicd-runtime-testbed/actions/runs/32625240102) | 2026-08-23 |
| sensor-monitor | [33178589841](https://github.com/fiord/cicd-runtime-testbed/actions/runs/33178589841) | 2026-08-28 |
| sensor-enforce | [33178601723](https://github.com/fiord/cicd-runtime-testbed/actions/runs/33178601723) | 2026-08-28 |
| leak-scan | [32644433598](https://github.com/fiord/cicd-runtime-testbed/actions/runs/32644433598) | 2026-08-23 |

sensor-monitor / sensor-enforce については、**アーティファクトが失効する前に
`cicd-sensor-report.html` / `predicate.json` の中身を直接確認した**。
本文中の「実測」はその一次データに基づく。

---

## 1. 現状、何が測れていないか

| | falco (upstream) | falco (fork) | cicd-sensor |
|---|---|---|---|
| T1 検知 | ❌ ルール 0 本ロード、イベント 0 件 | △ 発火ルールは "Source Code Overwrite" 1 種のみ | ✅ 9 ルール / 17 hit |
| T1 kill | 機能なし | 機能なし | ✅ `result: "terminated"` を実測 |
| T2 証跡 | ❌ なし | △ アラート JSON のみ、プロセス系譜なし | ✅ 系譜・CEL 条件・MITRE タグまで記録 |
| T3 漏洩 | 判定不能 (観測対象が存在しない) | 判定不能 | ✅ 10 カナリア中 7 件を実測判定 |

**比較として成立していない核心は「falco 側が測定台に乗っていない」こと。**
T1/T2/T3 のいずれも、falco 側の数字は「検知性能が低い」ではなく
「検知エンジンが仕事をする状態になっていない」ことの反映になっている。

---

## 2. `falcosecurity/falco-actions` (upstream) に必要な修正

### F-1 【最優先 / PR を出すべき】CI/CD ルールのマウントパスが実ファイル位置と一致していない

> **状態: fork で修正済み (実機/CI で確認済み) / upstream には未報告。**
> commit `360d62c` (`fix(start): correct default CI/CD rules mount path`) で
> `${{github.action_path}}/rules/...` を `${{github.action_path}}/../rules/...`
> に修正した。本リポジトリの `live-forked` leg でのみ
> `/etc/falco/rules.d/cicd_rules.yaml | schema validation: ok` が出ることを
> CI 実機で確認済み。
>
> ただし **upstream への PR・issue は一切出していない**。fork branch
> `fix/cicd-rules-mount-path` は GitHub 上で `2d2cbda` を指し、testbed の
> live run から参照済みである。draft の PR 文面は fork 側の `PR_BODY.md` に
> 用意済み。4節「F-1 を upstream に PR」は
> 依然として最優先で未着手のまま。

`start/action.yaml` (upstream `main`, 2026-08-28 時点):

```yaml
MOUNT_CICD_DEFAULT_RULES="-v ${{github.action_path}}/rules/falco_cicd_rules.yaml:/etc/falco/rules.d/cicd_rules.yaml"
```

`falcosecurity/falco-actions/start@<ref>` の `github.action_path` は
`_actions/falcosecurity/falco-actions/<ref>/start` を指す。したがって
マウント元は `<ref>/start/rules/falco_cicd_rules.yaml` になるが、
**ファイルの実体はリポジトリ直下の `rules/falco_cicd_rules.yaml`** である。

存在しないパスを bind mount するため Docker が空ディレクトリを作り、Falco は

```
Loading rules from:
```

の後に何も列挙せずに起動する。**`cicd-rules: true` は無言で無効化される。**

**修正:**

```diff
-MOUNT_CICD_DEFAULT_RULES="-v ${{github.action_path}}/rules/falco_cicd_rules.yaml:/etc/falco/rules.d/cicd_rules.yaml"
+MOUNT_CICD_DEFAULT_RULES="-v ${{github.action_path}}/../rules/falco_cicd_rules.yaml:/etc/falco/rules.d/cicd_rules.yaml"
```

`fiord/falco-actions@fix/cicd-rules-mount-path` に適用済み。fork leg でのみ
`/etc/falco/rules.d/cicd_rules.yaml | schema validation: ok` が出ることを確認済み。

> **この修正は upstream に PR / issue として一切報告されていない。**
> 該当行は 2025-03-17 に追加されて以降 upstream で修正されておらず、
> `cicd-rules` を使っている利用者全員に影響する。本リポジトリの成果として
> 最も価値があるのはこの発見なので、**まず PR を出すこと**を推奨する。

### F-2 【必須】Falco イメージが `falcosecurity/falco-no-driver` にハードコードされている

> **状態: fork で修正済み (静的検証 + ローカル `docker run` 確認 / action 経由・
> CI 未実行)。**
> commit `0e4a9e9` (`fix(start,analyze): use maintained falcosecurity/falco image`)
> で `start`/`analyze` 双方に `falco-image` 入力 (string, 既定
> `falcosecurity/falco`) を追加し、ハードコードされていた `IMAGE=` 行を
> 差し替えた。あわせて commit `bdd62a7` (`fix(start): verify Falco container
> stays alive, not just started once`) で起動チェックを強化した: 旧チェックは
> `docker ps` で `running` を一度見た時点でループを抜けて成功扱いにするため、
> その直後に Falco がクラッシュしても検知できなかった。修正後は `running`
> 確認後さらに `sleep 3` して再チェックし、生きていなければログを出して
> 失敗させる。現行の実測と制約は `docs/INVESTIGATION.md` に集約する。
> `falcosecurity/falco:0.44.1` が既存の起動コマンドをそのまま受け付けることは
> ローカルの `docker run` で確認済みだが、`start`/`analyze` action 経由での
> 実行・CI での確認はまだ行っていない。

`falco-no-driver` の Docker Hub 数値タグは 0.39.2 で止まっており、
新しい engine を選べない。fork では `falco-image` 入力を追加し、既定を
`falcosecurity/falco` に変更した。

**修正:** イメージ名を入力化する (fork の実装をそのまま PR 可能)。

### F-3 【重要】ルールが 1 本もロードされなくても起動が成功扱いになる

> **状態: 対応済みだが、最初の実装に欠陥があり是正した (是正版は CI 未実行)。**
> 最初の実装 (commit `775e814`, `fix(start): fail the step when requested
> rules failed to load`) は、起動ログ全体に対して `docker logs falco | grep -c
> "schema validation: ok"` の件数を数え、0 件のときだけ失敗させるものだった。
> しかしこのチェックは実質無意味だった: Falco は組込みの
> `/etc/falco/falco_rules.yaml` と 3 つの設定ファイルに対して常に自身で
> `schema validation: ok` を出すため、件数が 0 になることはない。
>
> `falcosecurity/falco:0.44.1` を Docker で (1) 正常な CI/CD ルールマウントと
> (2) F-1 の空ディレクトリ失敗モードの両方で実行して確認した: 失敗モードでは
> `/etc/falco/rules.d/cicd_rules.yaml` の行が消えるだけで、
> `/etc/falco/falco_rules.yaml | schema validation: ok` は残る。つまり旧
> チェックは F-1 のような失敗を検知できない。
>
> 是正: 全件カウントではなく、実際に要求したマウント先
> (`/etc/falco/rules.d/cicd_rules.yaml` および/または
> `/etc/falco/rules.d/custom_rules.yaml`) を個別に確認する方式に変更した。
> **この是正版は action 経由での実行検証・CI での確認ともにまだ行っていない。**

F-1 の直接の帰結として、**「センサーは動いているが何も検知できない」状態が
成功として報告される**。CI のランタイムセキュリティとしては最悪の失敗モードで、
利用者は「攻撃が無かった」と誤読する。

**修正案:** `start` で Falco 起動後に
`Loading rules from:` 以降にロードされたルールファイル数を確認し、
`cicd-rules: true` または `custom-rule-file` を指定したのに 0 本だった場合は
ジョブを失敗させる (もしくは `::error::` を出す)。

### F-4 【任意】analyze モードに `cicd-rules` 相当の自動ロード経路が無い

> **状態: fork と本リポジトリの workflow に実装済み (CI 未実行)。**
> commit `bc91ce3` (`feat(analyze): add cicd-rules input matching start's`) で
> `analyze/action.yaml` に `cicd-rules` boolean 入力 (既定 true) を追加し、
> `start` と同じ要領で
> `${{github.action_path}}/../rules/falco_cicd_rules.yaml` をマウントする
> ようにした。
>
> `.github/workflows/falco-analyze.yml` も fork の `start` / `stop` /
> `analyze` を参照し、`cicd-rules: true` を渡す。旧来の外部 checkout と
> `custom-rule-file` 回避策は削除した。fork の replay 成功と
> `Loading rules from:` に同梱ルールが現れることは、次回 run で確認する。

### (参考) `required_engine_version` は問題ではなかった

`rules/falco_cicd_rules.yaml` は `required_engine_version: 0.43.0` を宣言しているが、
**engine 0.39.2 は実測でこれを拒否しなかった** (run 32625240102、
`/etc/falco/rules.d/custom_rules.yaml | schema validation: ok`)。
過去のドキュメントにあるこの仮説は実測で反証されている。upstream 側の修正は不要。

---

## 3. `cicd-runtime-testbed` (本リポジトリ) に必要な修正

### R-1 【最優先 / 修正内容を実機確認済み】`cicd-sensorctl` のリリースタグが誤っており、ルール検証が毎回スキップされている

> **状態: 対応済み (静的検証のみ / CI 未実行)。**
> `sensor-monitor.yml` / `sensor-enforce.yml` の両方で download タグを
> `releases/${CICD_SENSOR_VERSION}` に修正し、ワークフローレベルの
> `env: CICD_SENSOR_VERSION` を単一の source of truth として導入、
> 存在しない `cicd-sensorctl version` の呼び出しを削除した。
> セットアップ情報は `docs/SETUP.md` に置き、実測結果は
> `docs/INVESTIGATION.md` に記録する。
> なお本文は `falco-live.yml` にも同じ install ブロックがあるとしているが、
> 実際には `falco-live.yml` に `cicd-sensorctl` の install は**存在しない**
> (grep で確認)。対象は 2 ワークフローである。

現状 (`sensor-monitor.yml` / `sensor-enforce.yml` 共通。本文の `falco-live.yml` は誤り):

```bash
gh release download v0.0.38 --repo cicd-sensor/cicd-sensor \
    --pattern "cicd-sensor_*_linux_amd64.tar.gz" ...
```

全 run で `release not found` → `::warning::failed to download cicd-sensorctl` となり、
**`Validate .cicd-sensor/rules` は一度も実行されたことがない。**

原因は 2 つ:

1. `cicd-sensor/cicd-sensor` のリリースタグは `v0.0.45` ではなく
   **`releases/v0.0.45`** という形式である。
2. `v0.0.38` は **action 側 (`cicd-sensor-action`) のバージョン**であり、
   sensor 本体のバージョンではない。sensor 本体は v0.0.42〜v0.0.46。

**修正:**

```diff
-if gh release download v0.0.38 \
+if gh release download "releases/${CICD_SENSOR_VERSION}" \
     --repo cicd-sensor/cicd-sensor \
     --pattern "cicd-sensor_*_linux_amd64.tar.gz" \
     --dir "${RUNNER_TEMP}/cicd-sensorctl"; then
```

`CICD_SENSOR_VERSION` は action に渡している `cicd-sensor-version` と
同じ値 (現状 `v0.0.45`) を単一の source of truth として持たせる。

tar の中身は `cicd-sensorctl-linux-amd64` / `cicd-sensor-manager-linux-amd64` /
`cicd-sensor-linux-amd64` で、既存の `sudo install ... cicd-sensorctl-linux-amd64`
はそのまま正しい。**この修正で `rule validate` がローカルで通ることを確認済み**
(`OK: 1 file(s) bundled and validated`)。

あわせて、`cicd-sensorctl version` は存在しないサブコマンド (`unknown command: version`)
なので、この行は削除するか `cicd-sensorctl rule validate --help` 等に置き換える。

**なぜ最優先か:** この穴が塞がっていれば、sensor-enforce が 3 回連続で
kill に失敗した事故 (run 32388911992 / 32544606013 / 32545681004) は
すべてローカル検証で事前に防げていた。

### R-2 【高】`cicd-sensor-version` を v0.0.46 に上げ、`testbed_canary_http_host` を再有効化する

> **状態: 対応済み (ローカル実験で検証 / CI 未実行)。**
> `sensor-monitor.yml` / `sensor-enforce.yml` の `env: CICD_SENSOR_VERSION`
> を v0.0.46 に上げ、`Start cicd-sensor` に
> `with: cicd-sensor-version: ${{ env.CICD_SENSOR_VERSION }}` を明示追加
> (従来は入力を渡しておらず、action 側の既定値 v0.0.45 が使われていた)。
> `.cicd-sensor/rules/testbed.yaml` の `testbed_canary_http_host` を
> コメントアウトから復帰させ、「main にしかない」旨の陳腐化した
> コメントを実測結果に書き換えた。実測の要約は
> `docs/INVESTIGATION.md` に置く。
>
> ローカル実験 (同一バンドルを両バージョンの `cicd-sensorctl` に投入):
> v0.0.45 → `unsupported event type "http_request"` / exit 1、
> v0.0.46 → `OK: 1 file(s) bundled and validated` / exit 0。
> **未検証: agent が実際に http_request イベントを記録し、
> CANARY_URL_PATH / CANARY_URL_QUERY が観測できるか。**

`.cicd-sensor/rules/testbed.yaml` の `testbed_canary_http_host`
(`event_type: http_request`) は「リリース済みタグに未実装」を理由に
コメントアウトされている。これは v0.0.45 時点では正しかったが、
**v0.0.46 (2026-08-25 リリース) で `http_request` はサポートされた。**

手元の `cicd-sensorctl` で実測:

```
--- v0.0.45 ---
error: bundle: ruleset_id=... rule_id=testbed_canary_http_host: unsupported event type "http_request"
--- v0.0.46 ---
OK: 1 file(s) bundled and validated
```

**修正:**
1. 3 ワークフローの `cicd-sensor-version` を `v0.0.46` に更新。
2. `testbed_canary_http_host` のコメントアウトを解除。
3. R-1 の検証ステップを有効化した状態で回し、バンドル検証が通ることを CI で確認。

**効果:** `CANARY_URL_PATH` / `CANARY_URL_QUERY` は現在
「観測する場所が存在しない」ため T3 で恒久的に N/A になっている。
このルールが復活すれば **10 カナリア中 9 件が判定可能**になる。

> 併せて、当時の README / testbed.yaml のコメントにあった
> 「http_request 対応は main ブランチにしか存在しない」という記述は
> v0.0.46 のリリースにより古くなっているので更新すること。

### R-3 【高】falco 側の自己ノイズを除去する

> **状態: 対応済み (静的検証のみ / CI 未実行)。判断が入っているので要レビュー。**
> 「両ツールに同じ除外を適用する」ではなく、**ハーネス側をワークスペース
> 外に退避させる**方を選んだ。`scenarios/lib/common.sh` の
> `TESTBED_TMPDIR` を `/var/tmp/cicd-runtime-testbed`、`TESTBED_LOG` を
> `${TESTBED_TMPDIR}/testbed-log.jsonl` に変更 (falco-live.yml の回収側も
> 追随)。どちらのツールの設定にも触れていないため構造的に対称で、
> falco は出荷時ルールのまま測れる (cicd-sensor 側のルールは
> `path.endsWith(<basename>)` 照合なのでディレクトリに依存しない)。
> 理由と副作用は `docs/TEST-PLAN.md`「公平性: ハーネス自身のノイズの除去
> (R-3)」に記載。
>
> **副作用 (要確認)**: falco が 05-memfd-exec で唯一出していたアラートは
> `$TESTBED_TMPDIR` 配下のドライバ `.py` 作成に対する
> "Source Code Overwrite" だったため、この変更後 falco は 05 を
> 一切検知しなくなる。R-11 の扱いに反映済み。

fork leg の 240 件のアラートのうち **213 件 (89%) が
`${RUNNER_TEMP}/cicd-runtime-testbed-log.jsonl` への書き込み**、つまり
テストベッド自身のログ出力に対する "Source Code Overwrite" である。
この状態では falco の検知結果を評価できない。

**修正案 (いずれか):**
- `scenarios/lib/common.sh` の `TESTBED_LOG` の既定値を、falco の
  監視対象ディレクトリ外 (例: `/var/tmp/`) に移す。
  現状は `${RUNNER_TEMP:-/tmp}/cicd-runtime-testbed-log.jsonl`。
- もしくは falco に渡す custom rule で当該パスを除外する。

いずれにせよ **どちらのツールに対しても同じ除外を適用**し、
除外内容を `docs/TEST-PLAN.md` に明記すること (公平性の担保)。

### R-4 【高】falco 側に比較可能なルールセットを与える

> **状態: 一部対応 (方針変更あり) / 要レビュー。**
> 「cicd-sensor 相当の falco カスタムルールを手書きして渡す」案は
> **採用しなかった**。それは出荷時構成の比較ではなく「我々が何を書けるか」
> の比較になり、docs/SPEC.md §1 の目的から外れるため。
> 代わりに (1) `falco-live.yml` の観測アサートを拡張して標準ルールセットが
> ロードされているかを実測で記録し、(2) 結論の提示単位を「アラート件数」
> から「シナリオごとの Yes/No」に変え、(3) **「ルールセットの母数
> (6 対 64) が違うので検知件数の直接比較には意味が無い」ことを
> `docs/TEST-PLAN.md` に明記した** (本項が代替として要求している対応)。

fork leg でも analyze でも、発火したのは "Source Code Overwrite" ただ 1 種類。
一方 cicd-sensor は 9 種類のルールが発火している (下表)。
これは検知能力の差というより **ルールセットの母数の差**である
(cicd-sensor: `rule_count=64`、falco `falco_cicd_rules.yaml`: 少数)。

実測で cicd-sensor が検知し falco が検知しなかったもの:

| シナリオ | cicd-sensor が発火させたルール | falco |
|---|---|---|
| 01-credential-access | `aws_credential_read`, `docker_credential_read`, `proc_environ_read`, `anchored_credential_read`, `anchored_multi_family_credential_access` | なし |
| 03-npm-postinstall | `aws_credential_read` (node/postinstall 系譜つき) | なし |
| 04-persistence | `shell_rc_write` | "Source Code Overwrite" のみ |
| 02-exfil | (観測のみ、アラートなし) | なし |
| 05-memfd-exec | **なし** | "Source Code Overwrite" (ドライバ .py の作成のみ) |
| 06-anti-forensics | **なし** | なし |

**修正案:** falco 側にも同等の観点をカバーする custom rule を用意し、
`custom-rule-file` で両モードに渡す。最低限、
`falco_rules.yaml` (標準ルール) を live モードでもロードする構成にする
(現状 live では `cicd_rules.yaml` しかロードしていない。analyze では
標準ルールもロードされているが、それでも発火は 1 種類だった)。

ルールセットを揃えられない場合は、**「ルールセットの母数が違うので
検知件数の直接比較には意味が無い」ことを結論に明記する**こと。

### R-5 【高】判定結果を stdout にも出力する

> **状態: 対応済み (静的検証のみ / CI 未実行)。**
> 5 ワークフローの `{ ... } >> "$GITHUB_STEP_SUMMARY"` 23 箇所と
> 単発の `echo ... >> "$GITHUB_STEP_SUMMARY"` 9 箇所を
> `| tee -a "$GITHUB_STEP_SUMMARY"` に変更 (計 32 箇所)。
> python heredoc で summary に書いている 4 箇所には
> `open_summary()` (ファイルと stdout の両方に書く contextmanager) を
> 導入した。
> 事前に、対象ブロック内で変数代入や `$GITHUB_OUTPUT` / `$GITHUB_ENV`
> への書き込みが無いことを機械的に確認済み (パイプでサブシェル化される
> ため、あれば壊れる)。`set -o pipefail` 下でも終了ステータスは
> 従来のリダイレクト形と同じ (ブロックの終了ステータス) になる。

現状、ほぼ全ての verdict が `$GITHUB_STEP_SUMMARY` にしか書かれていない。
step summary は **check-runs API から取得できない**ため、
アーティファクト失効後は検証結果が一切復元できなくなる。

**修正:** すべての判定ステップで、summary への追記と同じ内容を
`echo` でも出す (`tee -a "$GITHUB_STEP_SUMMARY"` にする)。

### R-6 【中】テレメトリの保持期間を延ばす

> **状態: 対応済み (静的検証のみ / CI 未実行)。**
> `telemetry-falco-live-*` / `telemetry-falco-live-forked-0.44.1` /
> `telemetry-cicd-sensor-monitor` / `telemetry-cicd-sensor-enforce` /
> `leak-report-<run_id>` を `retention-days: 7` に変更。
> `telemetry-falco-analyze` だけは `upload_raw_capture` が true のとき
> **生の capture.scap を含む**ため、その場合に限り従来どおり 1 日に
> 戻す条件式にした:
> `retention-days: ${{ (inputs.upload_raw_capture == true || inputs.upload_raw_capture == 'true') && 1 || 7 }}`
> (boolean 入力が boolean で来る場合と文字列で来る場合の両方を受ける)。
> OSS action の既定保持期間を testbed 用に変えることは互換性を損なうため行わない。
> workflow 側で使用後の即時削除処理を維持する。

変更前は `retention-days: 1` のため、数日で全証跡が消えていた。
public repo での secret 露出を避ける設計意図は理解できるが、
**カナリアは全て偽値であり、`capture.scap` を削除する運用も既にある**ため、
`telemetry-*` (加工済み) の保持期間だけは 7〜30 日に延ばして良い。
生の `capture.scap` / `cicd-sensor-report.html` の即時削除は現状維持。

### R-7 【中】`assert` ジョブがアーティファクト欠損時も success を返す

> **状態: 対応済み (ローカルで機能テスト済み / CI 未実行)。**
> GitHub Actions には neutral / inconclusive というジョブ結論が無いため、
> 「検証できなかった」を **失敗** として扱い、success は
> 「検証した結果 action=terminate だった」場合だけに限定した。
> 判定ステップは終了コードで 3 状態を返す:
> `0 = verified_terminate` / `1 = verified_not_terminate` および `no_hit` /
> `2 = inconclusive` (report / attestation のどちらも取得できなかった)。
> 「入力が 1 つも無い (inconclusive)」と「入力はあるがヒットが無い
> (no_hit)」も区別している。

sensor-enforce の最新 run (33178601723) で実際に起きた:

```
##[error]The runner has received a shutdown signal.     ← enforce ジョブの post ステップが中断
Uploaded bytes 862                                       ← attestation のアップロードが未完了
...
##[error]Unable to download artifact(s): Artifact not found for name: cicd-sensor-attestation
```

`Download cicd-sensor-attestation (monitor_mode reality check)` は
`continue-on-error: true` のため、**reality check が実行できなかったにも関わらず
assert ジョブは success を報告した**。

**修正:** reality check の入力が 1 つも得られなかった場合は
`::warning::` ではなく明示的に「検証不能 (inconclusive)」として
ジョブ結果に反映する。少なくとも success とは区別すること。

### R-8 【中】monitor_mode reality check の一次ソースを attestation から HTML report に変える

> **状態: 対応済み (ローカルで機能テスト済み / CI 未実行)。**
> `cicd-sensor-report.html` の `window.REPORT_DATA` を一次ソース、
> `predicate.json` を補助ソースに入れ替えた (ダウンロードステップの
> 順序も入れ替え)。report から読めた場合は `result` フィールド
> (`terminated` 等) も summary に出す。
>
> ローカル機能テスト (合成入力): report=terminate かつ
> attestation=detect のとき report が勝って `verified_terminate` /
> exit 0、入力ゼロで `inconclusive` / exit 2、attestation のみ
> (detect) で `verified_not_terminate` / exit 1 を確認。

実測で判明した仕様:

- `predicate.json` (attestation) に載るのは **`action: detect` / `terminate` のヒットのみ**。
  `action: collect` のヒットは 1 件も載らない。
- `cicd-sensor-report.html` の `window.REPORT_DATA` には **全ヒット**が載る
  (monitor run: attestation 2 件 vs report 17 件)。

実際、sensor-enforce の report には

```json
{"rule_id": "testbed_kill_marker", "action": "terminate", "event_type": "file_open",
 "payload": {"is_write": true, "path": ".../cicd-sensor-killme.marker"}}
```

と `"result": "terminated"` が記録されており、
**attestation が失われた run でも report から reality check は可能だった。**

**修正:** reality check は `cicd-sensor-report.html` の `REPORT_DATA` を
一次ソースにし、attestation は補助にする。

### R-9 【低】leak-scan のカナリア照合を case-insensitive にする

> **状態: 対応済み (この作業以前から実装済み。ローカルで実証)。**
> `tools/scan-leaks.sh` は既にカナリア本走査を `grep -aFio`
> (大文字小文字非依存・固定文字列・バイナリ安全) で行なっており、
> `leak-report.json` に `"canary_match_mode": "case_insensitive"` を
> 出力している。念のためローカルで、小文字化された
> `cnry-dns-donotuse-18ebf5.test.invalid.<サーチドメイン>` に対して
> 元の大小文字混在のカナリア値がヒットすることを確認した (1 件)。
> **コード変更は行なっていない。**

DNS カナリアは telemetry 上で **小文字化されて**記録される:

```
cnry-dns-donotuse-18ebf5.test.invalid.<runner の Azure 内部サーチドメイン>
```

現状の照合が大小文字を区別していると、`CANARY_DNS` の漏洩を取りこぼす。
`grep -i` 相当にすること。

### R-10 【低】leak-scan を各検知ワークフローから自動起動する

> **状態: 対応済み (静的検証のみ / CI 未実行)。**
> `leak-scan.yml` に `workflow_run` トリガを追加し、falco-live /
> falco-analyze / sensor-monitor の完了で自動起動するようにした。
> 対象 run_id はワークフローレベルの
> `env: TARGET_RUN_ID: ${{ github.event_name == 'workflow_run' && github.event.workflow_run.id || inputs.run_id }}`
> に一本化し、以降のステップは `inputs.run_id` を直接参照しない。
> `conclusion` が cancelled / skipped の run はスキップするが、
> **failure はスキップしない** (テレメトリのアップロードは
> `if: always()` なので残っており、むしろ走査価値がある)。
>
> 本項が挙げるもう一方の案 (`gh workflow run`) は採れない:
> **GITHUB_TOKEN で起動した workflow_dispatch は GitHub の再帰防止に
> より新しい run を作らない** (エラーにもならず黙って何も起きない)。
> PAT を置くのは docs/SAFETY.md の方針に反するため、workflow_run に
> した。
>
> **制約 (要認識)**: `workflow_run` はデフォルトブランチ上のワークフロー
> 定義でしか発火しない。ブランチで検証している間は手動起動が必要。
> `docs/SETUP.md` / `docs/TEST-PLAN.md` にも明記した。

現在 leak-scan は `run_id` を手で渡す `workflow_dispatch` 専用で、
その結果 **cicd-sensor に対する T3 は 1 commit 前のツールコードでしか
測定されていない**。各ワークフローの最後に
`workflow_run` または `gh workflow run` で leak-scan を自動起動し、
「最新コードで全ツールを測った」状態を常に保つ。

### R-11 【要判断】どちらのツールも検知していないシナリオの扱い

> **状態: 対応済み (静的検証 + ローカル `cicd-sensorctl` 検証のみ / CI 未実行)。**
> **2 シナリオとも残す。落とさない。** ただし検知件数の比較からは除外し、
> 結果表では「両ツールの出荷時ルールセットでは未検知」と明示する。
>
> 判断の根拠: この「未検知」には 2 つのまったく違う意味がありうる。
>   1. センサーがそのイベントを**観測できていない** (見えていない)
>   2. イベントは観測できているが、**出荷時ルールセットに該当ルールが無い**
>      のでアラートにならない
> 出荷時構成の比較としては 2. も立派な結果だが、1. と混同したまま
> 「未カバー」と書くのは不誠実なので、切り分けの手段を仕込んだ。
>
> **cicd-sensor 側**: `.cicd-sensor/rules/testbed.yaml` に新しい ruleset
> `cicd_runtime_testbed/uncovered_scenarios` を追加し、`action: collect`
> の観測プローブを 2 本置いた。
>   - `testbed_probe_memfd_exec` — `event_type: process_exec` /
>     `condition: is_memfd` (05-memfd-exec の fileless exec を観測)
>   - `testbed_probe_evidence_removal` — `event_type: file_remove` /
>     `condition: path.endsWith("/05-memfd-driver.py")` (06-anti-forensics
>     の証拠削除を観測)
> ヒットすれば 2.、ヒットしなければ 1. と判定できる。
> どちらも `collect` なのでジョブは止めない。
> CEL のフィールド名はローカルの cicd-sensorctl v0.0.46 に実際に
> バンドルを投げて受理されることを確認した (`is_memfd` は **bare**。
> `process.is_memfd` / `file_remove` の `is_write` / `from_path` は
> **いずれも拒否される**)。
>
> **falco 側**: 対称な観測を独自ルールで書くことはしない (R-4 と同じ
> 理由: 手書きルールを足すと「出荷時に何が鳴るか」ではなく
> 「我々が何を書けるか」の測定になる)。falco の標準ルールセットには
> **"Fileless execution via memfd_create" (priority CRITICAL) が有効な
> 状態で最初から含まれている**ため、falco 側の問いは
> 「標準ルールセットがロードされているか」に還元される。これは R-4 で
> 追加した falco-live.yml の observational assert (`STD_RULES`) が
> そのまま答えになる。
>
> **両ツールで同じ問いにならない**点は注意が必要で、これ自体を
> 「出荷時構成の違い」として `docs/TEST-PLAN.md` に記録した。
> R-3 の副作用 (`$TESTBED_TMPDIR` をワークスペース外へ移したことで
> falco は 05 で何も検知しなくなる) もそこに併記してある。
>
> なお「シナリオが弱すぎるのか」という問いについては、**弱くはない**と
> 判断した。05 は `os.memfd_create` + `os.set_inheritable` +
> `execv("/proc/self/fd/N")` という、fileless 実行の教科書どおりの形で
> あり、falco の標準ルールが名指しで狙っている挙動そのものである。
> 検知されないのはシナリオの問題ではなく構成の問題である可能性が高い。

**05-memfd-exec** と **06-anti-forensics** は、実測で
**falco / cicd-sensor のどちらからも検知されていない**。

- シナリオが弱すぎる (単に `os.memfd_create` して `execv` するだけ) のか
- 両ツールが本当にカバーしていないのか

を切り分ける必要がある。切り分けができないなら、これらは
「両ツール未カバー」として結果表に明示的に残し、
検知件数の比較からは除外すること。

---

## 4. 優先順位と最小実行計画

本質的なテストを成立させるための最短経路:

| 順 | 項目 | 理由 |
|---|---|---|
| 1 | **F-1 を upstream に PR** | 本リポジトリ最大の成果であり、外部検証を受けていない唯一の重要発見 |
| 2 | **R-1** (cicd-sensorctl のタグ修正) | ルール検証が復活し、以後の設定事故が事前に止まる |
| 3 | **R-2** (v0.0.46 + http_request 再有効化) | T3 の N/A が 3 件 → 1 件に減る |
| 4 | **R-3 + R-4** (falco の自己ノイズ除去 + ルール母数を揃える) | ここまでやって初めて T1/T2 の「比較」が成立する |
| 5 | **R-5 + R-6** (stdout 出力 + 保持期間) | 結果が後から検証可能になる |
| 6 | R-7, R-8, R-9, R-10, R-11 | 判定の頑健性 |

1〜3 は 1 コミットずつで完了する。4 が本丸で、ここを通さない限り
**このリポジトリは「2 ツールの比較」ではなく「falco-actions のバグ報告」に留まる。**

---

## 5. 付録: 今回の実測で新たに確定した事実

sensor-monitor (33178589841) / sensor-enforce (33178601723) の
アーティファクトを失効前に取得して判明した、これまで未確認だった事項。

### T1: kill は monitor_mode をバイパスして本当に terminate されている

```json
"result_summary": {"result": "terminated"},
"hits": [{"rule_id": "testbed_kill_marker", "action": "terminate",
          "event_type": "file_open",
          "payload": {"flags": 33345, "is_read": false, "is_write": true,
                      "path": "/home/runner/work/_temp/cicd-runtime-testbed/cicd-sensor-killme.marker"}}]
```

ジョブ側は `exit code 130` (SIGINT) で停止し、`REACHED_AFTER_KILLME` は出力されず。
**記録された action は `detect` への降格ではなく `terminate` そのもの**であり、
`monitor_mode: false` が正しく効いていることが確認できた。

### T2: cicd-sensor のヒットが持つフィールド

```
timestamp / ruleset_id / rule_id / ruleset_revision / rule_name /
rule_description / rule_type / rule_condition / action / event_type /
process / payload
```

- `process` には pid, start_boottime, exec_path, argv に加えて
  **`ancestors` (Runner.Worker まで遡る系譜、各要素に argv 付き)** が入る。
- `rule_type` に `event` と **`correlation`** がある
  (`anchored_multi_family_credential_access` は他ルールの
  `total_count` を参照する相関ルール)。falco 側に相当機能なし。
- `rule_tags.mitre_tactic` (`credential-access`, `persistence`) が付く。
- `ruleset_revision` がルールセットの sha256。証跡の再現性が取れる。

falco 側の証跡はアラート JSON のみで、プロセス系譜は含まれない。
**T2 は現状、比較するまでもなく cicd-sensor が上回っている。**

### T3: redaction の実装メカニズムが判明

| 対象 | 実測された記録内容 |
|---|---|
| `argv` の各要素 | **先頭 12 文字で切り詰め**、残りを `<truncated, N bytes>` と表記 |
| 認証情報らしき argv | 要素ごと `<redacted>` に置換 (例: `["cat", "<redacted>"]`, `["-H", "<redacted>"]`) |
| DNS 名 | **切り詰めも伏せ字もなし。小文字化のみ** |
| ファイルパス (payload.path) | そのまま完全記録 |
| 環境変数 / ファイル内容 | **記録されない** |

実データに対するカナリア照合結果:

| カナリア | 値 | telemetry 中の出現 |
|---|---|---|
| `CANARY_ENV` | `CNRY-ENV-...` | 0 |
| `CANARY_FILE` | `CNRY-FILE-...` | 0 |
| `CANARY_PATH` | `CNRY-PATH-...` | **1** |
| `CANARY_ARGV_SHORT` | `CNRYQ7K2M9XZ` (12 バイト) | **1** |
| `CANARY_ARGV_LONG` | `CNRY-ARGVLONG-...` (29 バイト) | 0 (12 文字で切断) |
| `CANARY_ARGV_FLAG` | `CNRY-ARGVFLAG-...` | 0 (`<redacted>`) |
| `CANARY_URL_QUERY` / `CANARY_URL_PATH` | — | 0 (観測経路が無い → R-2 で解消可能) |
| `CANARY_DNS` | `CNRY-DNS-...` | **2** (小文字化されて記録) |
| `CANARY_SCAP` | — | 0 (falco 専用、対象外) |

`CANARY_ARGV_SHORT` が 12 バイトちょうどで設計されていたことにより、
**「12 文字切り詰め」という閾値が偶然ではなく正確に切り分けられた。**
カナリア設計としては成功している。
