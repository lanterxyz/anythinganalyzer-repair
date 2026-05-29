import * as forge from "node-forge";
import * as crypto from "crypto";
import * as tls from "tls";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";
import { join } from "path";

// node-forge encodes BOOLEAN TRUE as 0xFF, but DER (X.690 §11.1) requires 0x01.
// Android BoringSSL enforces strict DER and may reject certs with 0xFF booleans.
// Monkey-patch forge.asn1.create to fix this at the source before any cert is built.
const _origAsn1Create = forge.asn1.create;
forge.asn1.create = function (
  cls: number,
  type: number,
  constructed: boolean,
  value: string,
  options?: Record<string, unknown>,
) {
  if (
    type === forge.asn1.Type.BOOLEAN &&
    typeof value === "string" &&
    value.charCodeAt(0) === 0xff
  ) {
    value = String.fromCharCode(0x01);
  }
  return _origAsn1Create.call(this, cls, type, constructed, value, options);
};

const CA_KEY_FILE = "ca-key.pem";
const CA_CERT_FILE = "ca-cert.pem";
const CA_VALIDITY_YEARS = 10;
const LEAF_VALIDITY_DAYS = 825; // Apple max
const CACHE_MAX_SIZE = 500;

/**
 * Increment this when the CA generation logic changes (e.g., different extensions,
 * issuer format fix). Existing CA certs on disk will be regenerated automatically.
 */
const CA_VERSION = 9;
const CA_VERSION_FILE = "ca-version.txt";

/**
 * CaManager — Generates and caches a root CA certificate,
 * then issues per-host leaf certificates on demand for MITM TLS interception.
 */
export class CaManager {
  private caKey: forge.pki.rsa.KeyPair | null = null;
  private caCert: forge.pki.Certificate | null = null;
  /** LRU-ish cache: hostname → tls.SecureContext */
  private contextCache = new Map<string, tls.SecureContext>();

  private _caRegenerated = false;

  constructor(private certsDir: string) {}

  /** Whether the last init() call regenerated the CA (version mismatch). */
  wasCaRegenerated(): boolean {
    return this._caRegenerated;
  }

  /**
   * Load existing CA from disk, or generate a new one.
   */
  async init(): Promise<void> {
    this._caRegenerated = false;

    if (!existsSync(this.certsDir)) {
      mkdirSync(this.certsDir, { recursive: true });
    }

    const keyPath = join(this.certsDir, CA_KEY_FILE);
    const certPath = join(this.certsDir, CA_CERT_FILE);
    const versionPath = join(this.certsDir, CA_VERSION_FILE);

    // Regenerate if version mismatch or files missing
    const versionMatch =
      existsSync(versionPath) &&
      readFileSync(versionPath, "utf-8").trim() === String(CA_VERSION);

    if (
      existsSync(keyPath) &&
      existsSync(certPath) &&
      versionMatch
    ) {
      const keyPem = readFileSync(keyPath, "utf-8");
      const certPem = readFileSync(certPath, "utf-8");
      const privateKey = forge.pki.privateKeyFromPem(keyPem);
      this.caKey = {
        privateKey,
        publicKey: forge.pki.setRsaPublicKey(privateKey.n, privateKey.e),
      } as forge.pki.rsa.KeyPair;
      this.caCert = forge.pki.certificateFromPem(certPem);
      this.printCAFingerprint();
    } else {
      // Version mismatch or missing — regenerate CA
      if (existsSync(keyPath) || existsSync(certPath)) {
        console.log("[CaManager] CA version changed, regenerating root certificate");
      }
      await this.generate();
      writeFileSync(versionPath, String(CA_VERSION), "utf-8");
      this._caRegenerated = true;
      this.printCAFingerprint();
    }
  }

  isInitialized(): boolean {
    return this.caCert !== null && this.caKey !== null;
  }

  /**
   * Log the CA certificate fingerprint so users can verify the .0 file
   * installed on Android matches the proxy's current CA.
   */
  private printCAFingerprint(): void {
    if (!this.caCert) return;
    const skiExt = this.caCert.extensions.find((e: { name: string }) => e.name === "subjectKeyIdentifier");
    const ski = skiExt ? (skiExt as Record<string, unknown>).subjectKeyIdentifier as string : "unknown";
    const hash = this.getSubjectHashOld();
    console.log(
      `[CaManager] CA fingerprint: SKI=${ski}  file=${hash}.0` +
      (this._caRegenerated ? " (REGENERATED - reinstall on Android!)" : ""),
    );
  }

  getCaCertPath(): string {
    return join(this.certsDir, CA_CERT_FILE);
  }

  /**
   * Get the CA certificate in DER (binary) format for mobile download.
   */
  getCaCertDer(): Buffer {
    if (!this.caCert) throw new Error("CA not initialized");
    const asn1 = forge.pki.certificateToAsn1(this.caCert);
    const der = forge.asn1.toDer(asn1);
    return Buffer.from(der.getBytes(), "binary");
  }

  /**
   * Compute the OpenSSL subject_hash_old for the CA certificate.
   * This is MD5(DER-encoded subject DN) with the first 4 bytes in little-endian.
   * Used for naming the file in Android's /system/etc/security/cacerts/ directory.
   */
  getSubjectHashOld(): string {
    if (!this.caCert) throw new Error("CA not initialized");
    const certAsn1 = forge.pki.certificateToAsn1(this.caCert);
    const tbsCert = certAsn1.value[0] as forge.asn1.Asn1;
    // TBSCertificate: [0]version, serial, sigAlgo, issuer, validity, subject, ...
    const subjectAsn1 = tbsCert.value[5] as forge.asn1.Asn1;
    const subjectDer = forge.asn1.toDer(subjectAsn1);
    const subjectDerBuf = Buffer.from(subjectDer.getBytes(), "binary");
    const md5 = crypto.createHash("md5").update(subjectDerBuf).digest();
    return md5.readUInt32LE(0).toString(16).padStart(8, "0");
  }

  /**
   * Get (or create) a TLS SecureContext for the given hostname.
   */
  getSecureContextForHost(hostname: string): tls.SecureContext {
    const cached = this.contextCache.get(hostname);
    if (cached) return cached;

    // Evict oldest if cache full
    if (this.contextCache.size >= CACHE_MAX_SIZE) {
      const oldest = this.contextCache.keys().next().value!;
      this.contextCache.delete(oldest);
    }

    const { key, cert } = this.issueLeafCert(hostname);
    const ctx = tls.createSecureContext({
      key,
      cert,
    });
    this.contextCache.set(hostname, ctx);
    return ctx;
  }

  /**
   * Delete existing CA, generate a new one, clear cache.
   */
  async regenerate(): Promise<void> {
    this.contextCache.clear();
    await this.generate();
  }

  // ---- Private ----

  private async generate(): Promise<void> {
    const keys = forge.pki.rsa.generateKeyPair({ bits: 2048 });
    this.caKey = keys;

    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = this.randomSerial();

    const now = new Date();
    cert.validity.notBefore = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    cert.validity.notAfter = new Date(
      Date.UTC(
        now.getUTCFullYear() + CA_VALIDITY_YEARS,
        now.getUTCMonth(),
        now.getUTCDate(),
        now.getUTCHours(),
        now.getUTCMinutes(),
        now.getUTCSeconds(),
      ),
    );

    const attrs: forge.pki.CertificateField[] = [
      { shortName: "O", value: "Anything Analyzer", valueTagClass: forge.asn1.Type.UTF8 },
      { shortName: "CN", value: "Anything Analyzer CA", valueTagClass: forge.asn1.Type.UTF8 },
    ];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);

    cert.setExtensions([
      { name: "basicConstraints", cA: true, critical: true },
      {
        name: "keyUsage",
        keyCertSign: true,
        cRLSign: true,
        critical: true,
      },
      {
        name: "subjectKeyIdentifier",
      },
      {
        name: "authorityKeyIdentifier",
        keyIdentifier: true,
      },
    ]);

    cert.sign(keys.privateKey, forge.md.sha256.create());
    this.caCert = cert;

    // Persist — convert CRLF to LF for Android system cert compatibility
    const keyPem = forge.pki.privateKeyToPem(keys.privateKey).replace(/\r\n/g, "\n");
    const certPem = forge.pki.certificateToPem(cert).replace(/\r\n/g, "\n");
    writeFileSync(join(this.certsDir, CA_KEY_FILE), keyPem, "utf-8");
    writeFileSync(join(this.certsDir, CA_CERT_FILE), certPem, "utf-8");
  }

  private issueLeafCert(hostname: string): { key: string; cert: string } {
    if (!this.caKey || !this.caCert) {
      throw new Error("CA not initialized");
    }

    // Generate a unique key pair for each leaf certificate.
    // Sharing the CA key pair for leaf certs is rejected by Android BoringSSL.
    const keys = forge.pki.rsa.generateKeyPair({ bits: 2048 });
    const cert = forge.pki.createCertificate();

    cert.publicKey = keys.publicKey;
    cert.serialNumber = this.randomSerial();

    const now = new Date();
    cert.validity.notBefore = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    cert.validity.notAfter = new Date(
      Date.UTC(
        now.getUTCFullYear(),
        now.getUTCMonth(),
        now.getUTCDate() + LEAF_VALIDITY_DAYS,
        now.getUTCHours(),
        now.getUTCMinutes(),
        now.getUTCSeconds(),
      ),
    );

    cert.setSubject([{ shortName: "CN", value: hostname, valueTagClass: forge.asn1.Type.UTF8 }]);
    cert.setIssuer([
      { shortName: "O", value: "Anything Analyzer", valueTagClass: forge.asn1.Type.UTF8 },
      { shortName: "CN", value: "Anything Analyzer CA", valueTagClass: forge.asn1.Type.UTF8 },
    ]);

    // SAN: support both DNS name and IP address
    const isIP = /^[\d.]+$/.test(hostname) || hostname.includes(":");
    const altNames: { type: number; value?: string; ip?: string }[] = isIP
      ? [{ type: 7, ip: hostname }]
      : [{ type: 2, value: hostname }];

    // Build authorityKeyIdentifier from the CA certificate's subjectKeyIdentifier.
    // Forge stores SKI as a hex string (40 chars). node-forge's authorityKeyIdentifier
    // handler expects keyIdentifier to be raw bytes (not an ASN1 object).
    const caSkiExt = this.caCert.extensions.find(
      (e: { name: string }) => e.name === "subjectKeyIdentifier",
    );
    let caSkiRaw: string | undefined;
    if (caSkiExt) {
      const skiHex = (caSkiExt as Record<string, unknown>).subjectKeyIdentifier;
      if (typeof skiHex === "string" && skiHex.length > 0) {
        caSkiRaw = forge.util.hexToBytes(skiHex);
      }
    }

    cert.setExtensions([
      { name: "basicConstraints", cA: false },
      {
        name: "keyUsage",
        digitalSignature: true,
        keyEncipherment: true,
        critical: true,
      },
      { name: "extKeyUsage", serverAuth: true },
      { name: "subjectAltName", altNames },
      { name: "subjectKeyIdentifier" },
      {
        name: "authorityKeyIdentifier",
        ...(caSkiRaw ? { keyIdentifier: caSkiRaw } : { keyIdentifier: false }),
      },
    ]);

    cert.sign(this.caKey.privateKey, forge.md.sha256.create());

    // Only send leaf cert — root CA must already be in client trust store.
    // Including root in chain can cause Android BoringSSL to reject it.
    const leafPem = forge.pki.certificateToPem(cert).replace(/\r\n/g, "\n");
    return {
      key: forge.pki.privateKeyToPem(keys.privateKey).replace(/\r\n/g, "\n"),
      cert: leafPem,
    };
  }

  private randomSerial(): string {
    const bytes = forge.random.getBytesSync(16);
    // If the first byte has its high bit set, the DER INTEGER will be
    // interpreted as negative. Prepend a 0x00 byte to keep it positive.
    // This is required by X.690 DER and enforced by Android BoringSSL.
    if (bytes.charCodeAt(0) >= 0x80) {
      return forge.util.bytesToHex("\x00" + bytes);
    }
    return forge.util.bytesToHex(bytes);
  }
}
