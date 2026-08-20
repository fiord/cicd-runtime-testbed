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
    lines.append("")
    lines.append("| カナリア ID | 注入経路 | 期待 | 実測 | 判定 |")
    lines.append("| --- | --- | --- | --- | --- |")

    findings = report.get("findings", [])
    findings_by_id = {f.get("canary_id"): f for f in findings}

    mismatches = 0
    mismatch_details = []
    na_count = 0
    rendered_ids = set()

    def render_row(canary_id, finding):
        nonlocal mismatches, na_count
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

    lines.append("")
    lines.append(render_runner_token_section(report))

    return "\n".join(lines) + "\n", mismatches, mismatch_details, na_count


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

    table_md, mismatches, mismatch_details, na_count = render(report)

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
    na_suffix = " (%d N/A)" % na_count if na_count else ""
    print(
        "RESULT: %d canaries checked%s, %d mismatch(es) -> exit %d"
        % (len(findings), na_suffix, mismatches, 1 if mismatches else 0)
    )

    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
