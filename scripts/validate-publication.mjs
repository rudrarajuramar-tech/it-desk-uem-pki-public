import { execFileSync } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { existsSync, lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const expectedOrigin = "https://rudrarajuramar-tech.github.io/it-desk-uem-pki-public";
export const artifactPaths = new Map([
  ["root-certificate", "pki/root/itdesk-uem-root-ca.der"],
  ["root-crl", "pki/root/itdesk-uem-root-ca.crl"],
  ["issuing-certificate", "pki/issuing/itdesk-uem-issuing-ca.der"],
  ["issuing-crl", "pki/issuing/itdesk-uem-issuing-ca.crl"],
]);

const forbiddenExtensions = new Set([".key", ".pem", ".pfx", ".p12", ".p8", ".pk8", ".jks", ".keystore", ".csr", ".req", ".srl"]);
const textExtensions = new Set(["", ".html", ".json", ".md", ".mjs", ".txt", ".yml", ".yaml", ".gitignore"]);
const secretPatterns = [
  /-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/i,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bASIA[0-9A-Z]{16}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,
];

function extensionOf(path) {
  const name = path.split("/").at(-1);
  const index = name.lastIndexOf(".");
  return index < 0 ? "" : name.slice(index).toLowerCase();
}

export function isForbiddenPath(path) {
  const normalized = String(path).replaceAll("\\", "/").toLowerCase();
  const parts = normalized.split("/");
  return parts.some((part) => part === ".env" || part.startsWith(".env.") || part === "private" || part === "secrets" || part.startsWith("credentials") || part === "id_rsa" || part === "id_ed25519")
    || forbiddenExtensions.has(extensionOf(normalized));
}

export function containsForbiddenText(text) {
  return secretPatterns.some((pattern) => pattern.test(String(text)));
}

function exactProperties(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const observed = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(observed) !== JSON.stringify(wanted)) throw new Error(`${label} has an invalid property set`);
}

function safeRelativePath(value, label) {
  const path = String(value || "");
  if (!path || path.includes("\\") || path.startsWith("/") || path.split("/").some((part) => !part || part === "." || part === "..")) {
    throw new Error(`${label} is not a safe relative path`);
  }
  return path;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function filesUnder(root) {
  const files = [];
  function visit(directory) {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.name === ".git") continue;
      const fullPath = join(directory, entry.name);
      const stat = lstatSync(fullPath);
      if (stat.isSymbolicLink()) throw new Error(`Symbolic links are prohibited: ${relative(root, fullPath)}`);
      if (stat.isDirectory()) visit(fullPath);
      else if (stat.isFile()) files.push(fullPath);
      else throw new Error(`Unsupported filesystem object: ${relative(root, fullPath)}`);
    }
  }
  visit(root);
  return files;
}

function assertRepositoryBoundary(root) {
  const allowedRoots = new Set([".github", "public", "schemas", "scripts"]);
  const allowedRootFiles = new Set([".gitattributes", ".gitignore", "package.json", "package-lock.json", "POLICY.md", "README.md", "SECURITY.md"]);
  for (const fullPath of filesUnder(root)) {
    const path = relative(root, fullPath).split(sep).join("/");
    const top = path.split("/")[0];
    if (!allowedRoots.has(top) && !allowedRootFiles.has(path)) throw new Error(`File is outside the publication repository allowlist: ${path}`);
    if (isForbiddenPath(path)) throw new Error(`Private-material path is prohibited: ${path}`);
    const stat = lstatSync(fullPath);
    if (stat.size > 8 * 1024 * 1024) throw new Error(`File exceeds the public repository size boundary: ${path}`);
    if (textExtensions.has(extensionOf(path)) && containsForbiddenText(readFileSync(fullPath, "utf8"))) {
      throw new Error(`Private-key or credential pattern detected: ${path}`);
    }
  }
}

function requireDate(value, label) {
  const parsed = Date.parse(String(value || ""));
  if (!Number.isFinite(parsed) || !String(value).endsWith("Z")) throw new Error(`${label} must be an explicit UTC timestamp`);
  return parsed;
}

function validateArtifactMetadata(artifact) {
  const certificate = artifact.type.endsWith("certificate");
  const properties = certificate
    ? ["path", "type", "sha256", "fingerprintSha256", "serialHex", "notBefore", "notAfter"]
    : ["path", "type", "sha256", "issuerFingerprintSha256", "crlNumber", "thisUpdate", "nextUpdate"];
  exactProperties(artifact, properties, `artifact ${artifact.type || "unknown"}`);
  if (!artifactPaths.has(artifact.type)) throw new Error(`Unsupported artifact type: ${artifact.type}`);
  if (safeRelativePath(artifact.path, "artifact path") !== artifactPaths.get(artifact.type)) throw new Error(`Artifact path does not match its type: ${artifact.type}`);
  if (!/^[a-f0-9]{64}$/.test(artifact.sha256)) throw new Error(`Artifact SHA-256 is invalid: ${artifact.type}`);
  if (certificate) {
    if (!/^[a-f0-9]{64}$/.test(artifact.fingerprintSha256)) throw new Error(`Certificate fingerprint is invalid: ${artifact.type}`);
    if (!/^[1-9a-f][a-f0-9]{15,63}$/.test(artifact.serialHex)) throw new Error(`Certificate serial is invalid: ${artifact.type}`);
    if (requireDate(artifact.notAfter, "notAfter") <= requireDate(artifact.notBefore, "notBefore")) throw new Error(`Certificate validity is invalid: ${artifact.type}`);
  } else {
    if (!/^[a-f0-9]{64}$/.test(artifact.issuerFingerprintSha256)) throw new Error(`CRL issuer fingerprint is invalid: ${artifact.type}`);
    if (!/^[1-9a-f][a-f0-9]{0,31}$/.test(artifact.crlNumber)) throw new Error(`CRL number is invalid: ${artifact.type}`);
    if (requireDate(artifact.nextUpdate, "nextUpdate") <= requireDate(artifact.thisUpdate, "thisUpdate")) throw new Error(`CRL validity is invalid: ${artifact.type}`);
  }
}

function openssl(args) {
  return execFileSync("openssl", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}

function validateActiveArtifacts(publicRoot, artifacts) {
  const temporary = mkdtempSync(join(tmpdir(), "itdesk-uem-pki-"));
  try {
    const byType = new Map(artifacts.map((artifact) => [artifact.type, artifact]));
    const certificatePem = new Map();
    for (const type of ["root-certificate", "issuing-certificate"]) {
      const artifact = byType.get(type);
      const fullPath = resolve(publicRoot, artifact.path);
      const bytes = readFileSync(fullPath);
      const certificate = new X509Certificate(bytes);
      if (!certificate.ca) throw new Error(`${type} is not a CA certificate`);
      if (certificate.fingerprint256.replaceAll(":", "").toLowerCase() !== artifact.fingerprintSha256) throw new Error(`${type} fingerprint does not match manifest`);
      if (certificate.serialNumber.toLowerCase() !== artifact.serialHex) throw new Error(`${type} serial does not match manifest`);
      if (Date.parse(certificate.validFrom) !== Date.parse(artifact.notBefore) || Date.parse(certificate.validTo) !== Date.parse(artifact.notAfter)) throw new Error(`${type} validity does not match manifest`);
      const pemPath = join(temporary, `${type}.pem`);
      writeFileSync(pemPath, certificate.toString(), { mode: 0o600 });
      certificatePem.set(type, pemPath);
    }
    const root = new X509Certificate(readFileSync(resolve(publicRoot, byType.get("root-certificate").path)));
    const issuer = new X509Certificate(readFileSync(resolve(publicRoot, byType.get("issuing-certificate").path)));
    if (!root.checkIssued(root) || !root.verify(root.publicKey)) throw new Error("Root certificate is not self-issued and self-signed");
    if (!root.checkIssued(issuer) || !issuer.verify(root.publicKey)) throw new Error("Issuing certificate is not signed by the published root");
    openssl(["verify", "-CAfile", certificatePem.get("root-certificate"), certificatePem.get("issuing-certificate")]);

    for (const [crlType, issuerType] of [["root-crl", "root-certificate"], ["issuing-crl", "issuing-certificate"]]) {
      const artifact = byType.get(crlType);
      const fullPath = resolve(publicRoot, artifact.path);
      const pemPath = join(temporary, `${crlType}.pem`);
      openssl(["crl", "-inform", "DER", "-in", fullPath, "-out", pemPath]);
      openssl(["crl", "-in", pemPath, "-noout", "-verify", "-CAfile", certificatePem.get(issuerType)]);
      if (artifact.issuerFingerprintSha256 !== byType.get(issuerType).fingerprintSha256) throw new Error(`${crlType} issuer fingerprint does not match its CA`);
      const metadata = openssl(["crl", "-in", pemPath, "-noout", "-crlnumber", "-lastupdate", "-nextupdate"]);
      const number = metadata.match(/^crlNumber=0x([0-9a-f]+)$/im)?.[1]?.toLowerCase();
      const thisUpdate = metadata.match(/^lastUpdate=(.+)$/im)?.[1]?.trim();
      const nextUpdate = metadata.match(/^nextUpdate=(.+)$/im)?.[1]?.trim();
      if (!number || number !== artifact.crlNumber) throw new Error(`${crlType} number does not match manifest`);
      if (!thisUpdate || Date.parse(thisUpdate) !== Date.parse(artifact.thisUpdate)) throw new Error(`${crlType} thisUpdate does not match manifest`);
      if (!nextUpdate || Date.parse(nextUpdate) !== Date.parse(artifact.nextUpdate)) throw new Error(`${crlType} nextUpdate does not match manifest`);
    }
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

export function validateRepository(repositoryRoot) {
  const root = resolve(repositoryRoot);
  assertRepositoryBoundary(root);
  const schemaPath = join(root, "schemas", "publication-manifest.schema.json");
  JSON.parse(readFileSync(schemaPath, "utf8"));
  const publicRoot = join(root, "public");
  const manifest = JSON.parse(readFileSync(join(publicRoot, "pki", "manifest.json"), "utf8"));
  exactProperties(manifest, ["schemaVersion", "publication", "status", "origin", "artifacts"], "manifest");
  if (manifest.schemaVersion !== 1 || manifest.publication !== "it-desk-uem-pki-public-v1" || manifest.origin !== expectedOrigin) throw new Error("Manifest identity is invalid");
  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length > 4) throw new Error("Manifest artifacts are invalid");
  const types = new Set();
  for (const artifact of manifest.artifacts) {
    validateArtifactMetadata(artifact);
    if (types.has(artifact.type)) throw new Error(`Duplicate artifact type: ${artifact.type}`);
    types.add(artifact.type);
    const fullPath = resolve(publicRoot, artifact.path);
    if (!fullPath.startsWith(`${publicRoot}${sep}`) || !existsSync(fullPath) || !lstatSync(fullPath).isFile()) throw new Error(`Manifest artifact is unavailable: ${artifact.path}`);
    const bytes = readFileSync(fullPath);
    if (sha256(bytes) !== artifact.sha256) throw new Error(`Artifact hash does not match manifest: ${artifact.type}`);
  }
  const allowedPublic = new Set([".nojekyll", "index.html", "robots.txt", "pki/manifest.json", ...manifest.artifacts.map((artifact) => artifact.path)]);
  for (const fullPath of filesUnder(publicRoot)) {
    const path = relative(publicRoot, fullPath).split(sep).join("/");
    if (!allowedPublic.has(path)) throw new Error(`Unmanifested public file is prohibited: ${path}`);
  }
  if (manifest.status === "bootstrap-no-ca-material") {
    if (manifest.artifacts.length !== 0) throw new Error("Bootstrap publication cannot contain PKI artifacts");
  } else if (manifest.status === "active") {
    if (types.size !== artifactPaths.size || [...artifactPaths.keys()].some((type) => !types.has(type))) throw new Error("Active publication requires the complete CA certificate and CRL set");
    validateActiveArtifacts(publicRoot, manifest.artifacts);
  } else {
    throw new Error("Manifest status is invalid");
  }
  return { status: "pass", publication: manifest.publication, mode: manifest.status, artifacts: manifest.artifacts.length };
}

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    console.log(JSON.stringify(validateRepository(repositoryRoot)));
  } catch (error) {
    console.error(String(error?.message || error));
    process.exitCode = 1;
  }
}
