#!/usr/bin/env node
/*
 * scenarios/03-npm-postinstall/postinstall.js
 *
 * 用途:
 *   npm の postinstall ライフサイクルスクリプトから、クレデンシャルアクセス
 *   と外部通信を行なう。プロセス系譜検知能力を試す中核シナリオ。
 *   `npm install --no-audit --no-fund ./scenarios/03-npm-postinstall`
 *   のように、ローカルパッケージとしてインストールされたときにのみ動く。
 *   npm レジストリからは何も取得しない (依存関係ゼロ、Node.js 組み込み
 *   モジュールのみ使用)。
 *
 * 安全性 (docs/SPEC.md 1節を厳守):
 *   - 読むのは 00-seed.sh が用意した偽の ~/.aws/credentials のみ。
 *     内容は意図的に破棄する (パスへのアクセスだけを発生させ、値を
 *     どこにも出力しない)。
 *   - 通信先は http://example.com/ のみ (IANA 予約ドメイン)。GET のみ、
 *     送信内容はなし。
 *   - このスクリプトはどんな経路で失敗しても常に成功扱いで終了する
 *     (npm install 自体を失敗させないため)。
 *
 * 期待される検知内容:
 *   cicd-sensor が「npm の子孫であること」を条件に含むルール
 *   (docs: rule-event-types.md の process.ancestors / descendants 例、
 *   generic-credential-access.yaml の anchored_credential_read など) で
 *   検知する想定。falco-actions は系譜4世代まで output に出すが、
 *   ルール条件としては使っていないため、汎用ルールでしか引っかからない
 *   はず。両者の表現力の差が最も明確に出るシナリオ。
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');

function safe(label, fn) {
  try {
    fn();
  } catch (err) {
    // 失敗しても npm install 自体は継続・成功させる。
    console.log(
      '[cicd-runtime-testbed] scenario step "' + label +
      '" failed (non-fatal): ' + (err && err.message ? err.message : err)
    );
  }
}

safe('read-fake-aws-credentials', () => {
  const credPath = path.join(os.homedir(), '.aws', 'credentials');
  // 内容は意図的に破棄する。CANARY_FILE (ファイル内容) は漏れない想定の
  // カナリアであり、このスクリプト自身がその値をログに出したり
  // どこかへ送信したりしてはならない。
  fs.readFileSync(credPath);
});

safe('outbound-http-to-example-com', () => {
  const req = http.get(
    'http://example.com/',
    { timeout: 5000 },
    (res) => {
      res.resume(); // レスポンス本文は破棄する
    }
  );
  req.on('timeout', () => req.destroy());
  req.on('error', () => {
    // ネットワークが使えない環境でも postinstall を失敗させない。
  });
});

// このスクリプトの失敗が npm install を失敗させないよう、常に 0 で終了する。
process.exitCode = 0;
