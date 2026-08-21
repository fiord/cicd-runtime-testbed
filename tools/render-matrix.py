#!/usr/bin/env python3
"""tools/render-matrix.py

用途:
  tools/scan-leaks.sh が生成した leak-report.json を読み、
  docs/SPEC.md 3節の「注入経路 / 期待結果」表と実測を突き合わせた
  Markdown 表を $GITHUB_STEP_SUMMARY (または指定した出力先) に書き出す。

安全性:
  読み取り専用。leak-report.json は canary_id のみを含み実値を含まない
  ため (tools/scan-leaks.sh 側の設計)、このスクリプトが新たな漏洩源に
  なることはない。外部通信は行わない。runner_token_findings も同様に
  パターン種別・件数・ファイル名のみで実値を含まない。

期待される検知内容:
  検知シナリオではない。T3 (secret 漏洩検証) の判定結果を CI 上で
  可視化するためのレポーター。期待 == 実測 なら OK、乖離していれば
  警告とし、警告が1件でもあれば非ゼロ終了で CI 上に問題を目立たせる
  (docs/SPEC.md 7節)。

  leak-report.json の `runner_token_findings` (ランナー由来トークンの
  パターン検出。カナリア走査とは別枠) は、上記のカナリア・マトリクスとは
  独立した別セクションとして出力する。これは「発見」であって「期待との
  乖離」ではないため、exit code には一切影響させない
  (mismatches のカウントはカナリアの findings のみを対象にする)。

Usage:
  tools/render-matrix.py [leak-report.json] [--out FILE]
  (--out を省略しても、$GITHUB_STEP_SUMMARY が設定されている場合は
  そちらにも書き込むが、標準出力への出力は常に行なう。
  $GITHUB_STEP_SUMMARY 未設定の場合は標準出力のみに出す)

終了コード:
  0 = 全カナリアが期待どおり（乖離なし）
  1 = 期待と実測の乖離あり（＝調査上の「発見」。CI 上で目立たせるための
      意図的な非ゼロ終了。docs/SPEC.md §7 参照）
  2 = 走査不成立（scanned_file_count が 0、または
      leak-report.json に scanned_file_count キーが無く、かつ全カナリアが
      found=false。走査対象アーティファクトが無かった/ダウンロードに
      失敗した等でテスト自体が成立していない状態。カナリアの乖離判定は
      行なわない）

  走査対象テレメトリの種別 (scan_root 配下のディレクトリ名から判定) に、
  あるカナリアが意味を持つツール (docs/SPEC.md §3「適用範囲」) が含まれて
  いない場合、そのカナリアは ⚠️ ではなく N/A (対象外) と表示され、
  mismatches のカウントにも exit code にも算入しない (例: falco 固有の
  CANARY_SCAP を cicd-sensor 単独の run に対して走査した場合)。

  さらに (実地実行 run 32381640678 で判明した問題への対応)、上記の
  「ツール種別による N/A」とは独立に「証跡の粒度による N/A」も判定する。
  cicd-sensor の standalone モードで得られる attestation predicate は
  **集計のみ** (個別イベントの timestamp / argv / プロセスツリー、ファイル
  アクセスのパス、collect アクションのヒット、HTTP の path/host 等を
  一切含まない。cicd-sensor のドキュメントにも明記されている仕様) であり、
  predicate.json しか無い状況では `CANARY_PATH` / `CANARY_FILE` /
  `CANARY_ARGV_SHORT` / `CANARY_ARGV_LONG` / `CANARY_ARGV_FLAG` /
  `CANARY_URL_QUERY` / `CANARY_URL_PATH` は原理的に観測できない
  (「漏れなかった」のではなく「見る場所が無い」)。これらは、走査対象に
  cicd-sensor-report (HTML レポート) や falco の詳細テレメトリ
  (falco_events.json・抽出ファイル等) といった、集計より詳細な証跡が
  一つも含まれていない場合に限り、⚠️ ではなく N/A (証跡粒度不足) と表示し、
  mismatches のカウントにも exit code にも算入しない。`CANARY_DNS` は
  predicate の domains 配列に載る (今回の実地実行で確認した唯一の有効な
  観測) ため、この N/A 判定の対象には含めない。ツール種別による N/A と
  証跡粒度による N/A は独立した仕組みであり、両方が同時に働く
  (一方が先に N/A と判定していれば、そちらの理由を優先して表示する)。

Python 3 標準ライブラリのみを使用する。外部依存を追加しないこと。
"""
import json
import os
import sys

# canary_id -> 注入経路 (docs/SPEC.md 3節の表と同じ表現)
CANARY_ROUTES = {
    "CANARY_ENV": "環境変数 (GitHub Secrets 経由)",
    "CANARY_FILE": "ファイル内容 (~/.aws/credentials)",
    "CANARY_PATH": "ファイルパス (/tmp/CNRY.../marker)",
    "CANARY_ARGV_SHORT": "プロセス argv (12 バイト以下・キーワードなし)",
    "CANARY_ARGV_LONG": "プロセス argv (13 バイト以上・キーワードなし)",
    "CANARY_ARGV_FLAG": 'プロセス argv (--header "Authorization: Bearer ...")',
    "CANARY_URL_QUERY": "平文 HTTP のクエリ文字列",
    "CANARY_URL_PATH": "平文 HTTP のパス",
    "CANARY_DNS": "DNS クエリのラベル (*.test.invalid)",
    "CANARY_SCAP": "生の syscall バッファ (falco capture.scap)",
}

# 表示順は docs/SPEC.md 3節の表の並びに合わせる。
CANARY_ORDER = list(CANARY_ROUTES.keys())

# canary_id -> どのツールのテレメトリで期待値が意味を持つか (docs/SPEC.md
# §3「適用範囲」列 / §7 参照)。
#
# 各カナリアの expected は「どのツールを見ているか」に依存する。例えば
# CANARY_SCAP の expected=leak は「falco の capture.scap でのみ」という
# 条件付きの期待であり、cicd-sensor 単独の run (capture.scap を作らない)
# を対象に走査すると、この条件を満たしようがないため必ず found=false に
# なる。これは「期待と実測が食い違った (発見)」ではなく「そもそも判定
# できない組み合わせ (対象外)」なので、他のカナリアと同じ ⚠️ 扱いに
# してはいけない。
#
# 判断に迷うものは「両方に適用」を既定にする (N/A で見逃すより、⚠️ で
# 気づける方が安全なため)。明確にツール固有と言えるのは CANARY_SCAP の
# みで、それ以外は cicd-sensor 側の redaction 挙動の検証が主目的だが、
# falco 側のテレメトリに現れることも観測対象として有意なため両方を対象に
# する。
TOOL_CICD_SENSOR = "cicd-sensor"
TOOL_FALCO = "falco"
BOTH_TOOLS = frozenset({TOOL_CICD_SENSOR, TOOL_FALCO})

CANARY_APPLIES_TO = {
    "CANARY_ENV": BOTH_TOOLS,
    "CANARY_FILE": BOTH_TOOLS,
    "CANARY_PATH": BOTH_TOOLS,
    "CANARY_ARGV_SHORT": BOTH_TOOLS,
    "CANARY_ARGV_LONG": BOTH_TOOLS,
    "CANARY_ARGV_FLAG": BOTH_TOOLS,
    "CANARY_URL_QUERY": BOTH_TOOLS,
    "CANARY_URL_PATH": BOTH_TOOLS,
    "CANARY_DNS": BOTH_TOOLS,
    "CANARY_SCAP": frozenset({TOOL_FALCO}),
}

# --- 証跡粒度による N/A 判定 (docs/SPEC.md §7「対象外（N/A）判定」後半) -------
#
# cicd-sensor の standalone モード (Manager なし) で得られる証跡は、
# attestation predicate (集計のみ) と HTML レポート (詳細) の 2 種類しかない
# (docs/SPEC.md §6)。predicate は個別イベントの timestamp / argv /
# プロセスツリー、ファイルアクセスのパス、`collect` アクションのヒット、
# HTTP の path/host を一切含まない仕様であることが cicd-sensor の
# ドキュメントに明記されている。実地実行 (run 32381640678) でこれを実際に
# 確認した: predicate.json だけがアーティファクトに含まれており、
# `testbed_detect_marker` (file_open ルール) が発火したことは分かっても
# どのファイルだったかは分からなかった (fileAccess 未実装)。
#
# このため、predicate 相当の集計レベルの証跡しか走査対象に無い場合、
# 集計レベルでは原理的に観測できないカナリアを ⚠️ (期待との乖離) として
# 扱ってはいけない。「漏れなかった」のか「見る場所が無い」のかを
# 区別できないため、そのようなカナリアは N/A (証跡粒度不足) として
# mismatches にも exit code にも算入しない。
#
# 証跡粒度は 3 段階 (低い順): "aggregate" (集計。predicate のみ) <
# "detail" (詳細。cicd-sensor-report の HTML、または falco の
# falco_events.json・抽出ファイル等の個別イベント情報) < "raw" (生。
# falco の capture.scap)。個々のカナリアは、観測に最低限必要な粒度を
# GRANULARITY_RANK の値で表す。
GRANULARITY_RANK = {"none": 0, "aggregate": 1, "detail": 2, "raw": 3}
GRANULARITY_LABEL = {
    "none": "証跡なし",
    "aggregate": "集計レベル (attestation predicate のみ)",
    "detail": "詳細レベル (HTML レポート / 個別イベント情報あり)",
    "raw": "生キャプチャレベル (capture.scap あり)",
}

# 「詳細レベル (rank>=2) 以上の証跡が無いと原理的に観測できない」カナリア。
# docs/SPEC.md §3 の「観測に必要な証跡粒度」列、および今回の実地実行で
# 判明した predicate の仕様 (集計のみ・fileAccess 未実装・collect除外・
# HTTP path/host 未収録) に基づく。`CANARY_DNS` は predicate の domains
# 配列に載るため意図的にこの集合から除外している (集計レベルでも判定対象)。
# `CANARY_ENV` / `CANARY_SCAP` も意図的に含めていない
# (`CANARY_ENV` は「観測できるかどうか」よりは redaction/マスキングの
# 検証が主目的であり expected=no_leak なので集計レベルでも矛盾しない。
# `CANARY_SCAP` は既存の CANARY_APPLIES_TO による falco 固有 N/A 判定で
# 別途カバーされている。挙動変更の影響範囲を最小化するため、この2つは
# 対象に含めない判断とした)。
REQUIRES_DETAIL_OR_BETTER = frozenset(
    {
        "CANARY_PATH",
        "CANARY_FILE",
        "CANARY_ARGV_SHORT",
        "CANARY_ARGV_LONG",
        "CANARY_ARGV_FLAG",
        "CANARY_URL_QUERY",
        "CANARY_URL_PATH",
    }
)

MIN_GRANULARITY_FOR_JUDGEMENT = 2  # "detail" 以上でないと判定しない


def detect_evidence_granularity(report):
    """leak-report.json の `scan_root` 配下のディレクトリ構成から、実際に
    得られている証跡の粒度を判定する。

    戻り値: (rank, label, detail_lines)
      - rank: GRANULARITY_RANK の値 (int)。判定できた場合のみ int。
      - label: GRANULARITY_LABEL 相当の説明文字列。
      - detail_lines: 判定根拠 (見つかった/見つからなかったものの一覧)。

    判定できない場合 (scan_root にアクセスできない等) は (None, None, [])
    を返す。呼び出し側は None の場合、detect_present_tools と同様に
    安全側に倒して証跡粒度による N/A 判定を行なわないこと
    (N/A で見逃すより ⚠️ で気づける方が良いため)。
    """
    scan_root = report.get("scan_root")
    if not scan_root or not os.path.isdir(scan_root):
        return None, None, []
    try:
        top_entries = os.listdir(scan_root)
    except OSError:
        return None, None, []

    cicd_sensor_attestation_found = False
    cicd_sensor_report_found = False
    falco_any_found = False
    falco_raw_found = False

    for entry in top_entries:
        entry_path = os.path.join(scan_root, entry)
        if not os.path.isdir(entry_path):
            continue
        is_falco_dir = entry.startswith("telemetry-falco-")
        if is_falco_dir:
            falco_any_found = True
        for walk_root, _dirs, files in os.walk(entry_path):
            base = os.path.basename(walk_root)
            if base == "cicd-sensor-attestation":
                cicd_sensor_attestation_found = True
            if base == "cicd-sensor-report":
                cicd_sensor_report_found = True
            if is_falco_dir and "capture.scap" in files:
                falco_raw_found = True

    rank = 0
    if cicd_sensor_attestation_found:
        rank = max(rank, GRANULARITY_RANK["aggregate"])
    if cicd_sensor_report_found:
        rank = max(rank, GRANULARITY_RANK["detail"])
    if falco_any_found:
        # falco のテレメトリ (falco_events.json / 抽出ファイル等) は
        # capture.scap が無くても個別イベント相当の情報を含むため、
        # 集計のみの predicate よりは詳細な証跡として扱う。
        rank = max(rank, GRANULARITY_RANK["detail"])
    if falco_raw_found:
        rank = max(rank, GRANULARITY_RANK["raw"])

    label_by_rank = {v: k for k, v in GRANULARITY_RANK.items()}
    label = GRANULARITY_LABEL[label_by_rank[rank]]

    detail_lines = [
        "cicd-sensor-attestation (predicate.json): %s"
        % ("あり" if cicd_sensor_attestation_found else "なし"),
        "cicd-sensor-report (HTML): %s"
        % ("あり" if cicd_sensor_report_found else "なし"),
        "falco テレメトリ (telemetry-falco-*): %s"
        % ("あり" if falco_any_found else "なし"),
        "falco capture.scap (生キャプチャ): %s"
        % ("あり" if falco_raw_found else "なし"),
    ]

    return rank, label, detail_lines


# leak-scan.yml がダウンロードする telemetry-* アーティファクトのディレクトリ名
# (actions/download-artifact merge-multiple:false によりアーティファクト名
# そのままのサブディレクトリ名になる) の接頭辞 -> ツール種別。
# 実際のアーティファクト名は各ワークフローの "Upload telemetry-*" ステップ
# 参照 (telemetry-cicd-sensor-monitor / telemetry-cicd-sensor-enforce /
# telemetry-falco-live-<version> / telemetry-falco-analyze)。
TOOL_DIR_PREFIXES = (
    (TOOL_CICD_SENSOR, "telemetry-cicd-sensor-"),
    (TOOL_FALCO, "telemetry-falco-"),
)

EXPECTED_LABEL = {"leak": "漏れる", "no_leak": "漏れない"}

# pattern id (tools/scan-leaks.sh の runner_token_findings) -> 表示ラベル
TOKEN_PATTERN_LABELS = {
    "github_token": "GitHub トークン (ghs_/ghp_/gho_/ghu_/ghr_...)",
    "jwt": "JWT (eyJ... 形式。ACTIONS_RUNTIME_TOKEN 等)",
}


def load_report(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def detect_present_tools(report):
    """leak-report.json の `scan_root` 直下のディレクトリ名から、走査対象に
    含まれるツールの種別 (cicd-sensor / falco) を判定する。

    戻り値:
      - set: 判定できた場合、含まれていたツール種別の集合
              (空集合はありえない。呼び出し側は non-empty を前提にしてよい)
      - None: 判定できなかった場合 (scan_root が無い/アクセスできない、
              または直下のディレクトリ名が既知の telemetry-* パターンに
              一つも一致しなかった)。この場合、呼び出し側は安全側に倒して
              全カナリアを判定対象として扱うこと (N/A で見逃すより、⚠️ で
              気づける方が良いため。leak-report.json だけを後から別環境で
              見返すケース (scan_root がもう存在しない) も含む)。
    """
    scan_root = report.get("scan_root")
    if not scan_root or not os.path.isdir(scan_root):
        return None
    try:
        entries = os.listdir(scan_root)
    except OSError:
        return None

    present = set()
    for entry in entries:
        entry_path = os.path.join(scan_root, entry)
        if not os.path.isdir(entry_path):
            continue
        for tool, prefix in TOOL_DIR_PREFIXES:
            if entry.startswith(prefix):
                present.add(tool)

    return present or None


def render(report):
    present_tools = detect_present_tools(report)
    granularity_rank, granularity_label, granularity_detail_lines = (
        detect_evidence_granularity(report)
    )

    lines = []
    lines.append("## Leak scan matrix")
    lines.append("")
    lines.append("- scanned_at: `%s`" % report.get("scanned_at", "?"))
    lines.append("- run_id: `%s`" % report.get("run_id", "?"))
    if present_tools is not None:
        lines.append(
            "- 走査対象テレメトリの種別: %s"
            % ", ".join(sorted(present_tools))
        )
    else:
        lines.append(
            "- 走査対象テレメトリの種別: 判定不能 "
            "(`scan_root` にアクセスできないか、既知のディレクトリ名と"
            "一致するものが無かったため、安全側に倒して全カナリアを"
            "判定対象として扱う)"
        )
    # 今回の走査で利用できた証跡の粒度 (docs/SPEC.md §7 後半、実地実行
    # run 32381640678 で判明した問題への対応)。predicate 相当の集計レベル
    # しか無い場合、そのレベルでは原理的に観測できないカナリアが後続の表で
    # N/A (証跡粒度不足) になる理由をここで明示する。
    if granularity_rank is not None:
        lines.append("- 今回の走査で利用できた証跡の粒度: %s" % granularity_label)
        for detail_line in granularity_detail_lines:
            lines.append("  - %s" % detail_line)
    else:
        lines.append(
            "- 今回の走査で利用できた証跡の粒度: 判定不能 "
            "(`scan_root` にアクセスできないため。安全側に倒して"
            "証跡粒度による N/A 判定は行なわず、全カナリアを通常どおり判定する)"
        )
    lines.append("")
    lines.append("| カナリア ID | 注入経路 | 期待 | 実測 | 判定 |")
    lines.append("| --- | --- | --- | --- | --- |")

    findings = report.get("findings", [])
    findings_by_id = {f.get("canary_id"): f for f in findings}

    mismatches = 0
    mismatch_details = []
    na_count = 0
    granularity_na_count = 0
    rendered_ids = set()

    def render_row(canary_id, finding):
        nonlocal mismatches, na_count, granularity_na_count
        route = CANARY_ROUTES.get(canary_id, "(unknown route)")
        expected = finding.get("expected", "?")
        found = bool(finding.get("found", False))
        actual = "leak" if found else "no_leak"
        expected_label = EXPECTED_LABEL.get(expected, expected)
        actual_label = EXPECTED_LABEL.get(actual, actual)

        applies_to = CANARY_APPLIES_TO.get(canary_id, BOTH_TOOLS)
        if present_tools is not None and not (applies_to & present_tools):
            # 今回走査したテレメトリにこのカナリアが意味を持つツールが
            # 含まれていない (例: falco 固有の CANARY_SCAP を
            # cicd-sensor 単独の run に対して走査した場合)。⚠️ にはせず、
            # 乖離件数にも exit code にも算入しない。
            na_count += 1
            lines.append(
                "| `%s` | %s | %s | (対象外) | N/A (%s のテレメトリではないため) |"
                % (canary_id, route, expected_label, "/".join(sorted(applies_to)))
            )
            return

        # 証跡粒度による N/A 判定 (ツール種別による N/A とは独立、両方が働く。
        # モジュール冒頭コメントおよび REQUIRES_DETAIL_OR_BETTER の定義を参照)。
        if (
            canary_id in REQUIRES_DETAIL_OR_BETTER
            and granularity_rank is not None
            and granularity_rank < MIN_GRANULARITY_FOR_JUDGEMENT
        ):
            granularity_na_count += 1
            lines.append(
                "| `%s` | %s | %s | (観測不能) | "
                "N/A（この証跡粒度では観測不能。集計レベルの証跡しか無い） |"
                % (canary_id, route, expected_label)
            )
            return

        ok = expected == actual
        verdict = "✅" if ok else "⚠️"  # ✅ / ⚠️
        if not ok:
            mismatches += 1
            mismatch_details.append((canary_id, expected_label, actual_label))
        lines.append(
            "| `%s` | %s | %s | %s | %s |"
            % (canary_id, route, expected_label, actual_label, verdict)
        )

    for canary_id in CANARY_ORDER:
        if canary_id in findings_by_id:
            render_row(canary_id, findings_by_id[canary_id])
            rendered_ids.add(canary_id)

    # レポートに未知の canary_id が含まれていても取りこぼさない。
    for finding in findings:
        canary_id = finding.get("canary_id")
        if canary_id not in rendered_ids:
            render_row(canary_id, finding)
            rendered_ids.add(canary_id)

    lines.append("")
    lines.append(
        "注: `CANARY_SCAP` は falco の `capture.scap` (生 syscall バッファ) "
        "でのみ漏れることが期待されている。上表は「どこかで見つかったか」の"
        "二値判定なので、capture.scap 以外の場所で見つかった場合も表面上は"
        "同じ OK 表示になる。詳細は leak-report.json の `locations` を"
        "確認すること。"
    )
    lines.append("")

    if mismatches:
        lines.append(
            "⚠️ %d 件の乖離があります。仮説と実測を確認してください。"
            % mismatches
        )
    else:
        lines.append("✅ すべてのカナリアが期待どおりの結果でした。")
    if na_count:
        lines.append(
            "ℹ️ %d 件は今回走査したテレメトリの種別が対象外のため N/A "
            "としました（⚠️ や exit code には算入していません）。"
            % na_count
        )
    if granularity_na_count:
        lines.append(
            "ℹ️ %d 件は今回の証跡粒度 (%s) では原理的に観測できないため "
            "N/A としました（⚠️ や exit code には算入していません。"
            "「漏れなかった」のではなく「見る場所が無い」ことに注意）。"
            % (
                granularity_na_count,
                granularity_label if granularity_label else "不明",
            )
        )

    lines.append("")
    lines.append(render_runner_token_section(report))

    return (
        "\n".join(lines) + "\n",
        mismatches,
        mismatch_details,
        na_count,
        granularity_na_count,
    )


def render_runner_token_section(report):
    """capture.scap 等に GitHub 発行の本物のトークンがパターンとして実際に
    入るかどうかの二次走査結果を、カナリア・マトリクスとは独立したセクション
    として描画する。

    これは「発見 (finding)」であって「期待との乖離 (mismatch)」ではない。
    呼び出し元の render() は、この関数の戻り値を exit code の判定材料に
    一切使わない (mismatches はカナリア側の findings のみで計算する)。
    """
    lines = []
    lines.append("## ランナー由来トークンのパターン検出 (参考情報)")
    lines.append("")
    lines.append(
        "capture.scap のようなランタイム由来の成果物に、GitHub が発行する"
        "本物のトークンが実際に (パターンとして) 混入するかどうかを見るための"
        "二次走査。上のカナリア・マトリクスとは別枠で、判定結果は ✅/⚠️ の"
        "対象にならず、**exit code にも影響しない**。実値は"
        "leak-report.json に書かれておらず、ここにも表示しない (パターン種別・"
        "件数・ファイル名のみ)。"
    )
    lines.append("")

    token_findings = report.get("runner_token_findings", [])
    if not token_findings:
        lines.append(
            "(runner_token_findings が leak-report.json に含まれていません。"
            "古い形式の leak-report.json、または走査対象が空だった可能性が"
            "あります。)"
        )
        return "\n".join(lines)

    any_hit = False
    lines.append("| パターン | 検出件数 | 検出ファイル |")
    lines.append("| --- | --- | --- |")
    for finding in token_findings:
        pattern_id = finding.get("pattern", "?")
        label = TOKEN_PATTERN_LABELS.get(pattern_id, pattern_id)
        count = finding.get("count", 0)
        locations = finding.get("locations", [])
        if count:
            any_hit = True
            files = ", ".join(
                "`%s` (%d)" % (loc.get("file", "?"), loc.get("count", 0))
                for loc in locations
            )
        else:
            files = "(検出なし)"
        lines.append("| %s | %d | %s |" % (label, count, files))

    lines.append("")
    if any_hit:
        lines.append(
            "🔎 ランナー発行トークンらしきパターンが検出されました。上表の"
            "「検出ファイル」に挙げたツールの出力に、対応する種類のトークンが"
            "その件数だけ含まれていたことを意味します。実値は記録していない"
            "ため、必要なら対象 run の該当アーティファクトを直接確認して"
            "ください。"
        )
    else:
        lines.append(
            "ランナー発行トークンらしきパターンは検出されませんでした。"
        )

    return "\n".join(lines)


def is_scan_not_established(report):
    """走査対象が実質空だったか (＝テストが成立していないか) を判定する。

    - `scanned_file_count` が 0 なら、走査対象ディレクトリが存在しても
      中身が空だったということなので、無条件に不成立とみなす。
    - `scanned_file_count` キーが無い場合 (旧形式の leak-report.json との
      後方互換) は、代わりに「全カナリアが found=false」であることを
      不成立の手がかりにする。ただし旧形式で本当に全部 no_leak として
      正しく判定されたケースと区別がつかないため、これは推測に過ぎない
      ことに注意 (docs/SPEC.md §7)。
    - `scanned_file_count` が 1 以上なら、たとえ全カナリアが
      found=false であっても、それ自体は正当な実測結果として扱う
      (不成立とはしない)。
    """
    scanned_file_count = report.get("scanned_file_count")
    findings = report.get("findings", [])

    if scanned_file_count == 0:
        return True

    if scanned_file_count is None:
        any_found = any(bool(f.get("found", False)) for f in findings)
        if not any_found:
            return True

    return False


def parse_args(argv):
    report_path = "leak-report.json"
    out_path = None
    i = 0
    while i < len(argv):
        if argv[i] == "--out":
            if i + 1 >= len(argv):
                raise SystemExit("error: --out requires a value")
            out_path = argv[i + 1]
            i += 2
            continue
        report_path = argv[i]
        i += 1
    return report_path, out_path


def write_summary(summary_path, text):
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write(text)


def main(argv):
    report_path, out_path = parse_args(argv)
    summary_path = out_path or os.environ.get("GITHUB_STEP_SUMMARY")

    if not os.path.isfile(report_path):
        print("error: leak report not found: %s" % report_path, file=sys.stderr)
        return 1

    try:
        report = load_report(report_path)
    except json.JSONDecodeError as exc:
        print("error: failed to parse %s: %s" % (report_path, exc), file=sys.stderr)
        return 1

    if is_scan_not_established(report):
        scanned_file_count = report.get("scanned_file_count", "(キーなし)")
        scan_root = report.get("scan_root", "(キーなし)")
        msg = (
            "走査対象のファイルが 0 件でした。対象 run に telemetry-* "
            "アーティファクトが存在しないか、ダウンロードに失敗した可能性が"
            "あります。カナリアの判定は行なっていません。"
            " (scanned_file_count=%s, scan_root=%s)"
            % (scanned_file_count, scan_root)
        )
        # 標準出力・stderr・job summary・::error:: の全経路に出す。
        # GITHUB_STEP_SUMMARY が設定されていても標準出力を省略しない
        # (これが今回の不具合の再発防止策そのもの)。
        print(msg)
        print(msg, file=sys.stderr)
        print("::error::%s" % msg)
        write_summary(
            summary_path,
            "## Leak scan matrix\n\n"
            "### ❌ 走査不成立 (テストが成立していません)\n\n"
            "%s\n" % msg,
        )
        print("RESULT: scan not established (scanned_file_count=%s) -> exit 2" % scanned_file_count)
        return 2

    table_md, mismatches, mismatch_details, na_count, granularity_na_count = render(
        report
    )

    # job summary に書く場合でも、同じ内容を必ず標準出力にも出す
    # (GITHUB_STEP_SUMMARY が設定されていてもステップのログが空にならない
    # ようにするため。これが今回の不具合の再発防止策そのもの)。
    write_summary(summary_path, table_md)
    print(table_md)

    if mismatches:
        for canary_id, expected_label, actual_label in mismatch_details:
            print(
                "::error::canary mismatch: %s expected=%s actual=%s"
                % (canary_id, expected_label, actual_label)
            )

    findings = report.get("findings", [])
    na_parts = []
    if na_count:
        na_parts.append("%d N/A tool" % na_count)
    if granularity_na_count:
        na_parts.append("%d N/A granularity" % granularity_na_count)
    na_suffix = " (%s)" % ", ".join(na_parts) if na_parts else ""
    print(
        "RESULT: %d canaries checked%s, %d mismatch(es) -> exit %d"
        % (len(findings), na_suffix, mismatches, 1 if mismatches else 0)
    )

    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
