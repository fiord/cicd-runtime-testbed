#!/usr/bin/env bash
#
# scenarios/05-memfd-exec.sh
#
# 用途:
#   fileless 実行 (memfd_create 経由の exec) を再現する。python3 の
#   組み込み os.memfd_create() で匿名メモリファイルを作り、無害な
#   シェルスクリプト (echo 相当) を書き込み、/proc/self/fd/<N> を
#   exec する。
#
# 実装上の注記 (SPEC に明記がないため、ここで補って設計した部分):
#   docs/SPEC.md の 06-anti-forensics.sh の説明に「05 で実行したバイナリを
#   削除する (falco の SHA256 計算が File does not exist anymore になる
#   ことの確認)」とあるが、memfd 経由の exec は本質的にディスク上の
#   パスを持たない (fileless) ため、"05 で実行したバイナリ" が指す実体が
#   SPEC 上明記されていない。ここでは、python3 に渡す「実行ドライバ
#   スクリプト」(memfd_create を呼び出す .py ファイル) を
#   $TESTBED_TMPDIR 配下の固定パスに置き、05 では削除せずに残す設計とした。
#   06-anti-forensics.sh がこの固定パスのファイルを削除することで、
#   「実行された (python3 に渡された) ファイルが後から消える」という
#   SPEC の意図する検証ができるようにしている。真の memfd 実行対象
#   (シェルスクリプトの中身) 自体はメモリ上にしか存在しないため、
#   別途削除すべきディスク上の実体はない。
#
# 安全性:
#   memfd に書き込み・実行する中身は `echo` 相当の無害な文字列表示のみ。
#   実際の窃取・権限昇格・回避コードは一切含まない。
#
# 期待される検知内容:
#   cicd-sensor の process_exec イベントで `is_memfd == true` が立つ想定。
#   falco 側で同等の情報 (memfd 由来の exec) が取得できるかを確認する。
#
# docs/SPEC.md 4節の要件どおり: set -uo pipefail (set -e は使わない)、
# 終了コードは常に 0。

set -uo pipefail

SCENARIO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCENARIO_DIR}/lib/common.sh"

load_canaries

step "memfd_create + write + exec /proc/self/fd/N (fileless exec of an echo-equivalent script)"

driver_path="${TESTBED_TMPDIR}/05-memfd-driver.py"

# このドライバファイル自体はディスク上に残す (06-anti-forensics.sh が
# 削除する対象となる)。memfd の中身 (実際に exec されるスクリプト) は
# メモリ上にのみ存在し、ディスクには書かれない。
cat > "${driver_path}" <<'PYEOF'
import os
import sys

try:
    fd = os.memfd_create("cicd_runtime_testbed_memfd")
except (AttributeError, OSError) as exc:
    print(
        "[cicd-runtime-testbed] memfd_create unavailable or failed: %s" % exc,
        file=sys.stderr,
    )
    sys.exit(0)

# Python 3.4+ (PEP 446) makes newly created file descriptors
# non-inheritable (close-on-exec) by default. Without this, fd would be
# closed the moment execv() replaces the process image, and the
# interpreter launched via the "#!/bin/sh" shebang would fail to reopen
# /proc/self/fd/<fd> ("No such file"). Explicitly mark it inheritable so
# it survives across the exec.
os.set_inheritable(fd, True)

# echo 相当の無害なシェルスクリプト。実際の窃取・回避コードは含まない。
payload = b"#!/bin/sh\necho '[cicd-runtime-testbed] memfd-exec scenario reached'\n"
os.write(fd, payload)
os.lseek(fd, 0, os.SEEK_SET)

fd_path = "/proc/self/fd/%d" % fd
try:
    os.execv(fd_path, [fd_path])
except OSError as exc:
    print(
        "[cicd-runtime-testbed] exec via memfd failed: %s" % exc,
        file=sys.stderr,
    )
    sys.exit(0)
PYEOF

safe_run python3 "${driver_path}"

note "left driver script at ${driver_path} on disk intentionally; scenarios/06-anti-forensics.sh removes it"
end_step

exit 0
