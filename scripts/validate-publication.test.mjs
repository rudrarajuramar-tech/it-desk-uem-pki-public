import assert from "node:assert/strict";
import test from "node:test";
import { containsForbiddenText, expectedOrigin, isForbiddenPath, validateRepository } from "./validate-publication.mjs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

test("bootstrap repository passes the public boundary", () => {
  assert.deepEqual(validateRepository(repositoryRoot), {
    status: "pass",
    publication: "it-desk-uem-pki-public-v1",
    mode: "bootstrap-no-ca-material",
    artifacts: 0,
  });
  assert.equal(expectedOrigin, "https://rudrarajuramar-tech.github.io/it-desk-uem-pki-public");
});

test("private material paths fail the denylist", () => {
  for (const path of ["private/root.key", "pki/issuer.pem", "certs/request.csr", ".env", ".env.production", "secrets/value.txt", "credentials-backup.json", "identity.p12", "id_ed25519"]) {
    assert.equal(isForbiddenPath(path), true, path);
  }
  for (const path of ["public/pki/root/itdesk-uem-root-ca.der", "public/pki/root/itdesk-uem-root-ca.crl", "POLICY.md"]) {
    assert.equal(isForbiddenPath(path), false, path);
  }
});

test("private key and hosted credential markers fail the content denylist", () => {
  assert.equal(containsForbiddenText(["-----BEGIN", "PRIVATE KEY-----"].join(" ")), true);
  assert.equal(containsForbiddenText(`github_pat_${"a".repeat(30)}`), true);
  assert.equal(containsForbiddenText(`ghp_${"a".repeat(30)}`), true);
  assert.equal(containsForbiddenText("public certificate and CRL"), false);
});
