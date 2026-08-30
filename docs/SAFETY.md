# SAFETY

このリポジトリを fork / 流用する場合に守るべき安全制約を、それぞれ「なぜそうするのか」
とともにまとめる。設計契約そのものは [`SPEC.md`](SPEC.md) §1 を参照。ここでは
理由を中心に書く。

このリポジトリは public GitHub repo 上で意図的に「攻撃者が行なうような操作の一部」
(クレデンシャルアクセス、外部通信、永続化、fileless 実行、証跡削除) を再現して、
falco-actions と cicd-sensor がそれをどこまで検知・記録・遮断できるかを確認する。
その性質上、通常のリポジトリより一段厳しい安全設計が必要になる。

## 1. 本物の秘密情報を一切使わない

**やること**: すべてのカナリア値は `CNRY-` プレフィックスの偽値にし、
`CANARY_ENV` を含めて GitHub Secrets に登録する値も偽物にする。

**理由**: このリポジトリは意図的に「クレデンシャルを読む」「外部に送る」動作を行なう。
本物の秘密情報を1つでも紛れ込ませると、検知の成否に関わらずその秘密情報自体が
実際に露出するリスクを負う。偽値であれば、たとえ検知に失敗して「漏洩」しても、
実害はゼロのまま「漏洩した」という事実だけを安全に観測できる。これがこの
リポジトリ全体の設計の前提になっている。

**fork する人が守ること**: 実在するクラウドの認証情報・API キー・トークンを
このリポジトリのどのファイルにも (テスト目的であっても) 書き込まないこと。
「テストだから」を理由に本物の低権限トークンを使うことも避けること
(低権限であっても、それが本物である以上、この設計の前提が崩れる)。

## 2. 実データを外部送信しない

**やること**: シナリオの通信先は `http://example.com/...` (IANA 予約ドメイン) と
`*.test.invalid` (RFC 2606 予約 TLD) の2つだけに限定し、URL / header / DNS label
には偽カナリアだけを載せる。

**理由**: 現行の `02-exfil.sh` は `example.com` へ **GET** を発行し、URL query /
path に偽カナリアを載せる。したがって「外部送信しない」ではなく、
**実在の secret を送らない**ことが正しい安全条件である。`example.com` は実験用の
予約ドメインだが、リクエスト path / query がサーバーや中継ログに残らない保証として
扱ってはならない。`.test.invalid` は RFC 2606 の予約 TLD であり登録済みの第三者
endpoint にはならないが、DNS resolver が query を観測する可能性まで否定しない。
webhook.site のような「送った内容を見せてくれる」サービスは、運営者に実データを
渡してしまう時点でこのリポジトリの安全設計と矛盾するため使わない。攻撃者インフラは
論外として、実在する第三者サービス全般をテストの通信先にしないという原則が背景にある。

**fork する人が守ること**: シナリオを追加・変更する際、通信先をこの2つ以外に
変えないこと。特に「もう少しリアルにしたいから」という理由で実在のドメインや
社内 webhook サービスに向けないこと。

**補足 (workflow 自身の外部通信について)**: `falco-live.yml` /
`falco-analyze.yml` は、falco-actions の action を呼ぶ前に Docker Hub tag API
を叩く preflight ステップを持つ。`live-forked` は `falcosecurity/falco`、
upstream / analyze は `falcosecurity/falco-no-driver` を確認する。また、
cicd-sensor の release download と artifact 回収・削除には GitHub API を使う。
これは検知シナリオが送信する「テスト対象の
通信」ではなく、ワークフロー自身が使う Docker イメージのタグが実在するかを
確認する**インフラ確認**であり、上記の「通信先は `example.com` /
`*.test.invalid` に限定する」という制約の対象外として扱う。カナリア値・
シークレット・シナリオ由来のデータは一切この API 呼び出しに含まれない
(送るのは falco-version 文字列の照合のみ)。preflight が失敗 (ネットワーク
障害・rate limit 等) しても、警告を出すだけでワークフローの実行自体は継続する
(preflight がテストの可用性を下げないため)。

## 3. 実在の IOC を踏まない

**やること**: cicd-sensor の `ioc.yaml` にある実際の悪性ドメイン・IP はテストに
使わない。kill テストは `.cicd-sensor/rules/testbed.yaml` の専用カスタムルールで発火させる。

**理由**: 実在の悪性 IOC 宛の通信を (たとえ失敗する前提でも) 発生させると、
そのトラフィック自体が監視システムや脅威インテリジェンス基盤に「本物の攻撃の痕跡」
として記録されうる。CI ランナーの IP レンジからそうした通信が発生すると、
GitHub 側やネットワーク監視側で不要なアラートや調査コストを発生させる可能性がある。
専用のカスタムルールを使えば、実在の IOC を一切使わずに「kill が起きるか」という
検証だけを独立に行なえる。

**fork する人が守ること**: kill テストの条件をより「リアル」にしたくなっても、
実在するマルウェアのハッシュ・C2 ドメイン・悪性 IP を rule の条件やシナリオに
組み込まないこと。

## 4. 汎用的な攻撃ツールを作らない

**やること**: 各シナリオは「観測されるべき syscall を発生させる最小のコマンド列」
とし、実際の窃取・権限昇格・回避を行なう機能を持たせない。各スクリプトの冒頭に
用途を明記したヘッダコメントを置く。

**理由**: このリポジトリの目的は「検知・遮断ツールの挙動を確認すること」であって
「攻撃ツールを作ること」ではない。同じ syscall パターンを再現するだけであれば、
実際に汎用化・再利用可能な攻撃コードにする必要はない。ヘッダコメントで用途を
明記するのは、後からこのリポジトリを読む人 (と、このリポジトリ自身を検知対象に
含めてしまうかもしれない別のセキュリティツール) が「これは攻撃ではなくテストである」
と判断できるようにするため。

**fork する人が守ること**: シナリオスクリプトを「もっと本物の攻撃っぽく」
拡張しないこと。目的は特定の syscall / イベントを発生させることであって、
実際に何かを盗む・壊す・回避する必要はない。

## 5. 成果物の保持期間と公開範囲を管理する

**現行実装**: 加工済み telemetry は `retention-days: 7`。ただし
`falco-analyze.yml` で `upload_raw_capture: true` のとき、raw `capture.scap` を
含む `telemetry-falco-analyze` だけは `retention-days: 1` である。

**理由**: このリポジトリのアーティファクトには、程度の差はあれ「漏洩したカナリア値」
や「実行環境の詳細」が含まれうる。保持期間が長いほど、意図しない第三者が
古いアーティファクトを見つけてダウンロードできる時間が長くなる。一方で実測の
比較には数日間の保持が必要なため、偽カナリアだけを含む加工済み telemetry は7日、
raw capture は1日という現行の分離を採る。

**fork する人が守ること**: 新しいワークフローやジョブを追加する際も
用途と内容に応じた `retention-days` を必ず明示すること。raw capture または
本物の情報を含み得る成果物を7日保持してはならない。falco-actions / cicd-sensor-action
のように、自分たちで retention-days を指定できないアクションを使う場合は、
`falco-analyze.yml` / `sensor-monitor.yml` / `sensor-enforce.yml` が行なっているように、
必要な情報だけを自分たちのアーティファクトにコピーしたうえで元のアーティファクトを
削除するなど、同等の効果を持つ代替策を検討すること。

## 6. 危険な成果物を既定でアップロードしない

**やること**: falco analyze モードの `capture.scap` は既定ではアップロードしない。
`workflow_dispatch` の入力 `upload_raw_capture: true` を明示指定したときのみ
アップロードする。

**理由**: `capture.scap` は snaplen 256 の生の syscall バッファをそのまま含む。
これは他のどの経路よりも「redaction されていない生データ」に近く、
`CANARY_SCAP` のように他の経路では漏れないはずの値までそのまま含まれる想定になっている。
public repo でこれを常時公開すると、意図しない情報漏洩の実演になってしまう。
既定でオフにし、明示的に有効化した場合だけ生成することで、「見たいときに見られるが、
うっかり誰でも見られる状態を常態化させない」という設計にしている。

**ただし完全な「既定でアップロードしない」は達成できていない**: `falco-actions` の
stop action (analyze モード) は `capture.scap` を無条件にアップロードし、
これを抑止する入力は存在しない。元リポジトリは変更しない方針のため、
`falco-analyze.yml` は「アップロード直後に GitHub API で削除する」方式で緩和している。
削除が完了するまでの数秒〜数十秒は、public repo では誰でもダウンロードできる。
この時間差は元アクションの実装に起因するもので、ワークフロー側では解消できない。

**`falco-analyze.yml` は public repo で実行してよく、ジョブを停止するガードは
存在しない**。以前のバージョンには「public かつ `upload_raw_capture: true` なら
ジョブを停止する」ガードがあったが、次の理由により過剰と判断して撤去した。

- `capture.scap` に入りうるカナリア値はすべて偽物で、リポジトリにコミット済み。
  公開されても失うものがない。
- このワークフローが実際に持つ本物の認証情報は次の2つだけである。
  - `GITHUB_TOKEN`: `record` job は `contents: read` のみだが、`analyze` job は
    falco-actions が作った `capture` / `hashes` artifact を削除するため
    `actions: write` も持つ。ジョブ完了時に失効するが、run 中に漏洩すれば
    このリポジトリの Actions artifact を削除できる権限として扱う。
  - `ACTIONS_RUNTIME_TOKEN`: run 中のみ有効な内部トークン。悪用の本命経路は
    `actions/cache` への汚染だが、このリポジトリは `actions/cache` を
    使っていないため、その経路自体が存在しない。
- `id-token: write` を宣言していないため `ACTIONS_ID_TOKEN_REQUEST_TOKEN` は存在しない。
- 残る主な権限リスクは、このテストリポジトリの Actions artifact の削除である。
  T3 (`capture.scap` から実際に何が漏れるかを観測する) の価値と、この短命だが
  `actions: write` を持つ token の露出リスクを比較して実行を判断する。

このワークフローは「`capture.scap` から実際に漏れること」を観測するのが目的であり、
漏洩を再現する作りになっている。上記の根拠により、その観測を public repo で行なってよい。
public repo で実行すると、`Notice: raw capture exposure on a public repository`
ステップが `::warning::` 注釈と job summary で「この run の `capture.scap` には
何が入るか」を告知する。**ジョブは停止しない。**

他の4本 (`falco-live.yml` / `sensor-monitor.yml` / `sensor-enforce.yml` /
`leak-scan.yml`) は生キャプチャを扱わないため、public でも実行してよい。

**この評価は、このリポジトリに本物の secret が無く、write 権限が raw artifact
削除に必要な `actions: write` に限られることに依存している。** 次のいずれかが
起きたら再評価すること。

- リポジトリに本物の secret を追加した場合
- `contents: write`、`id-token: write`、または artifact cleanup 以外の
  `actions: write` を宣言した場合
- `actions/cache` を使い始めた場合

**fork する人が守ること**: `upload_raw_capture: true` を既定値に変更しないこと。
上記の評価の前提 (本物の secret が無い、`actions: write` は raw artifact cleanup
に限定する、`actions/cache` を使っていない) を fork 先で変えるなら、public repo での
実行可否を自分で再評価すること。

---

## まとめ: fork / 流用する人へのチェックリスト

- [ ] 本物の秘密情報・API キー・トークンをどのファイルにも書き込んでいないか
- [ ] シナリオの通信先を `example.com` / `*.test.invalid` 以外に変えていないか。URL / header / DNS label が偽カナリアだけか
- [ ] 実在の IOC (悪性ドメイン・IP・ハッシュ) をシナリオやルールに混ぜていないか
- [ ] シナリオを実際に有害な攻撃コードへ拡張していないか
- [ ] 新しいアーティファクトに内容に応じた `retention-days`（通常7日、raw capture は1日）を明示したか
- [ ] `upload_raw_capture` を既定で有効にしていないか
- [ ] `falco-analyze.yml` を public repo で走らせる前提 (本物の secret が無い、
      `actions: write` は raw artifact cleanup に限定される、`actions/cache` を使っていない) を
      fork 先で崩していないか。崩した場合は public repo での実行可否を再評価したか
- [ ] トリガーを `push` / `pull_request` に変えていないか (`workflow_dispatch` のみを維持する)
- [ ] fork のブランチ参照 (`falco-live.yml` の `live-forked` ジョブが使う
      `fiord/falco-actions/start` / `stop@fix/cicd-rules-mount-path`) が、
      検証用の一時例外のまま残っていないか。検証が完了していれば
      コミット SHA pin に戻っているべき (docs/SPEC.md §8 参照)
