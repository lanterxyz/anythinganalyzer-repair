import forge from "node-forge";
import { readFileSync } from "node:fs";
import crypto from "node:crypto";

// Monkey-patch (same as ca-manager.ts)
const _origAsn1Create = forge.asn1.create;
forge.asn1.create = function (cls, type, constructed, value, options) {
  if (type === forge.asn1.Type.BOOLEAN && typeof value === "string" && value.charCodeAt(0) === 0xff) {
    value = String.fromCharCode(0x01);
  }
  return _origAsn1Create.call(this, cls, type, constructed, value, options);
};

// Load the user's actual CA cert
const caDer = readFileSync("/home/newnew/278ba3db.0");
// DER to ASN.1 to forge cert
const caAsn1 = forge.asn1.fromDer(caDer.toString("binary"));
const caCert = forge.pki.certificateFromAsn1(caAsn1);

console.log("=== User's CA Cert ===");
console.log("Subject:", caCert.subject.getField("CN")?.value);
console.log("Issuer:", caCert.issuer.getField("CN")?.value);

// Check extensions
console.log("\nExtensions:");
for (const ext of caCert.extensions) {
  console.log(`  - ${ext.name}`);
  if (ext.name === "subjectKeyIdentifier") {
    console.log(`    SKI hex: ${ext.subjectKeyIdentifier}`);
    console.log(`    SKI bytes: ${forge.util.hexToBytes(ext.subjectKeyIdentifier).length} bytes`);
  }
}

// Now simulate leaf cert generation exactly like ca-manager.ts does
const caSkiExt = caCert.extensions.find((e) => e.name === "subjectKeyIdentifier");
let caSkiRaw;
if (caSkiExt) {
  const skiHex = caSkiExt.subjectKeyIdentifier;
  if (typeof skiHex === "string" && skiHex.length > 0) {
    caSkiRaw = forge.util.hexToBytes(skiHex);
  }
}
console.log("\ncaSkiRaw length:", caSkiRaw?.length, "bytes");

// Now generate a test leaf cert
const hostname = "www.baidu.com";
const keys = forge.pki.rsa.generateKeyPair({ bits: 2048 });
const leafCert = forge.pki.createCertificate();
leafCert.publicKey = keys.publicKey;
leafCert.serialNumber = (() => {
  const bytes = forge.random.getBytesSync(16);
  if (bytes.charCodeAt(0) >= 0x80) return forge.util.bytesToHex("\x00" + bytes);
  return forge.util.bytesToHex(bytes);
})();
const now = new Date();
leafCert.validity.notBefore = new Date(now.getTime() - 24 * 60 * 60 * 1000);
leafCert.validity.notAfter = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 825, now.getUTCHours(), now.getUTCMinutes(), now.getUTCSeconds()));
leafCert.setSubject([{ shortName: "CN", value: hostname, valueTagClass: forge.asn1.Type.UTF8 }]);
leafCert.setIssuer([
  { shortName: "O", value: "Anything Analyzer", valueTagClass: forge.asn1.Type.UTF8 },
  { shortName: "CN", value: "Anything Analyzer CA", valueTagClass: forge.asn1.Type.UTF8 },
]);
const altNames = [{ type: 2, value: hostname }];
leafCert.setExtensions([
  { name: "basicConstraints", cA: false },
  { name: "keyUsage", digitalSignature: true, keyEncipherment: true, critical: true },
  { name: "extKeyUsage", serverAuth: true },
  { name: "subjectAltName", altNames },
  { name: "subjectKeyIdentifier" },
  { name: "authorityKeyIdentifier", ...(caSkiRaw ? { keyIdentifier: caSkiRaw } : { keyIdentifier: false }) },
]);

// We need the CA's PRIVATE KEY to sign, but we don't have it
// Instead, let's verify: if we had a leaf cert from the proxy, would its
// AKI match the CA's SKI?
console.log("\n=== Verification ===");
console.log("CA SKI:", caCert.extensions.find((e) => e.name === "subjectKeyIdentifier")?.subjectKeyIdentifier);
console.log("Would set leaf AKI to same bytes ✓");

// Also verify that CA cert chain is valid
const caSubject = caCert.subject.attributes;
console.log("\nCA subject attributes:");
for (const attr of caSubject) {
  console.log(`  ${attr.shortName || attr.name}: ${attr.value} (tagClass: ${attr.valueTagClass})`);
}

// Check subject hash
const tbsCert = forge.pki.certificateToAsn1(caCert).value[0];
const subjectAsn1 = tbsCert.value[5];
const subjectDer = forge.asn1.toDer(subjectAsn1);
const subjectDerBuf = Buffer.from(subjectDer.getBytes(), "binary");
const md5 = crypto.createHash("md5").update(subjectDerBuf).digest();
const hash = md5.readUInt32LE(0).toString(16).padStart(8, "0");
console.log("\nSubject hash old:", hash);
console.log("Filename should be:", hash + ".0");

// Verify matches openssl
import { execSync } from "node:child_process";
const opensslHash = execSync("openssl x509 -in /home/newnew/278ba3db.0 -inform DER -subject_hash_old -noout 2>&1").toString().trim();
console.log("OpenSSL subject hash:", opensslHash);
console.log("Match:", hash === opensslHash);

console.log("\n=== DONE ===");
