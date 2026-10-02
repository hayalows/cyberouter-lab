// End-to-end checks for the hosted website scanner boundary.
// Run: node test/e2e.mjs
// Set CYBEROUTER_E2E_NETWORK=1 to additionally scan a real public site.

import assert from "node:assert/strict";
import { auditPublicSite } from "../lib/site-audit.js";

let passed = 0;
let failed = 0;

async function expectBlocked(target, label) {
  try {
    await auditPublicSite(target, { mode: "passive" });
    failed += 1;
    console.error(`FAIL  ${label}: expected a block, but the scan was allowed`);
  } catch (error) {
    const message = String(error?.message || "");
    if (!message || /cannot|blocked|valid|supported|reserved|private|internal|resolve|credentials|standard web ports/i.test(message)) {
      passed += 1;
      console.log(`ok    ${label} → "${message}"`);
    } else {
      failed += 1;
      console.error(`FAIL  ${label}: unexpected error "${message}"`);
    }
  }
}

async function main() {
  // Localhost / loopback / private / reserved targets must be blocked before any connection.
  await expectBlocked("http://localhost", "localhost hostname");
  await expectBlocked("localhost:3000", "localhost with port");
  await expectBlocked("http://127.0.0.1", "IPv4 loopback");
  await expectBlocked("http://127.0.0.1:80/admin", "IPv4 loopback with path");
  await expectBlocked("http://10.0.0.5", "RFC1918 10/8");
  await expectBlocked("http://192.168.1.1", "RFC1918 192.168/16");
  await expectBlocked("http://172.16.4.4", "RFC1918 172.16/12");
  await expectBlocked("http://169.254.169.254/latest/meta-data", "cloud metadata link-local");
  await expectBlocked("http://0.0.0.0", "unspecified address");
  await expectBlocked("http://[::1]", "IPv6 loopback literal");
  await expectBlocked("http://[fc00::1]", "IPv6 unique local literal");
  await expectBlocked("http://[fe80::1]", "IPv6 link-local literal");
  await expectBlocked("http://[::ffff:127.0.0.1]", "IPv4-mapped loopback literal");
  await expectBlocked("http://metadata.google.internal", "internal metadata hostname");
  await expectBlocked("http://box.local", ".local hostname");
  await expectBlocked("http://example.com:8080", "non-standard port");
  await expectBlocked("http://user:pass@example.com", "credentials in URL");
  await expectBlocked("ftp://example.com", "non-HTTP scheme");
  await expectBlocked("not a url", "invalid URL");

  if (process.env.CYBEROUTER_E2E_NETWORK === "1") {
    const result = await auditPublicSite("https://example.com", { mode: "passive" });
    assert.ok(result.summary.pagesScanned >= 1, "expected at least one scanned page");
    assert.ok(Array.isArray(result.findings), "expected a findings array");
    assert.equal(result.scope.privateNetworkTargetsBlocked, true, "private-network blocking must stay on");
    assert.equal(result.scope.formSubmission, false, "form submission must stay off");
    assert.equal(result.scope.credentialAttacks, false, "credential attacks must stay off");
    assert.equal(result.scope.exploitPayloads, false, "exploit payloads must stay off");
    passed += 1;
    console.log(`ok    live passive scan of example.com → ${result.summary.pagesScanned} page(s), ${result.findings.length} finding(s)`);
  } else {
    console.log("skip  live network scan (set CYBEROUTER_E2E_NETWORK=1 to enable)");
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exitCode = 1;
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
