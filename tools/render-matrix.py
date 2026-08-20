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
  (--out を省略した場合は $GITHUB_STEP_SUMMARY。それも未設定なら標準出力)

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

EXPECTED_LABEL = {"leak": "漏れる", "no_leak": "漏れない"}

# pattern id (tools/scan-leaks.sh の runner_token_findings) -> 表示ラベル
TOKEN_PATTERN_LABELS = {
    "github_token": "GitHub トークン (ghs_/ghp_/gho_/ghu_/ghr_...)",
    "jwt": "JWT (eyJ... 形式。ACTIONS_RUNTIME_TOKEN 等)",
}


def load_report(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def render(report):
    lines = []
    lines.append("## Leak scan matrix")
    lines.append("")
    lines.append("- scanned_at: `%s`" % report.get("scanned_at", "?"))
    lines.append("- run_id: `%s`" % report.get("run_id", "?"))
    lines.append("")
    lines.append("| カナリア ID | 注入経路 | 期待 | 実測 | 判定 |")
    lines.append("| --- | --- | --- | --- | --- |")

    findings = report.get("findings", [])
    findings_by_id = {f.get("canary_id"): f for f in findings}

    mismatches = 0
    rendered_ids = set()

    def render_row(canary_id, finding):
        nonlocal mismatches
        route = CANARY_ROUTES.get(canary_id, "(unknown route)")
        expected = finding.get("expected", "?")
        found = bool(finding.get("found", False))
        actual = "leak" if found else "no_leak"
        expected_label = EXPECTED_LABEL.get(expected, expected)
        actual_label = EXPECTED_LABEL.get(actual, actual)
        ok = expected == actual
        verdict = "✅" if ok else "⚠️"  # ✅ / ⚠️
        if not ok:
            mismatches += 1
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

    lines.append("")
    lines.append(render_runner_token_section(report))

    return "\n".join(lines) + "\n", mismatches


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


def main(argv):
    report_path, out_path = parse_args(argv)

    if not os.path.isfile(report_path):
        print("error: leak report not found: %s" % report_path, file=sys.stderr)
        return 1

    try:
        report = load_report(report_path)
    except json.JSONDecodeError as exc:
        print("error: failed to parse %s: %s" % (report_path, exc), file=sys.stderr)
        return 1

    table_md, mismatches = render(report)

    summary_path = out_path or os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as f:
            f.write(table_md)
    else:
        print(table_md)

    return 1 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
