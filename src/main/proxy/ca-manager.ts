import * as forge from "node-forge";
import * as crypto from "crypto";
import * as tls from "tls";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";
import { join } from "path";

const CA_KEY_FILE = "ca-key.pem";
const CA_CERT_FILE = "ca-cert.pem";
const CA_VALIDITY_YEARS = 10;
const LEAF_VALIDITY_DAYS = 825; // Apple max
const CACHE_MAX_SIZE = 500;

/**
 * Increment this when the CA generation logic changes (e.g., different extensions,
 * issuer format fix). Existing CA certs on disk will be regenerated automatically.
 */
const CA_VERSION = 7;
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

  constructor(private certsDir: string) {}

  /**
   * Load existing CA from disk, or generate a new one.
   */
  async init(): Promise<void> {
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
    } else {
      // Version mismatch or missing — regenerate CA
      if (existsSync(keyPath) || existsSync(certPath)) {
        console.log("[CaManager] CA version changed, regenerating root certificate");
      }
      await this.generate();
      writeFileSync(versionPath, String(CA_VERSION), "utf-8");
    }
  }

  isInitialized(): boolean {
    return this.caCert !== null && this.caKey !== null;
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
      ca: forge.pki.certificateToPem(this.caCert!),
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
      { shortName: "CN", value: "Anything Analyzer CA" },
      { shortName: "O", value: "Anything Analyzer" },
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

    // Persist
    const keyPem = forge.pki.privateKeyToPem(keys.privateKey);
    const certPem = forge.pki.certificateToPem(cert);
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

    cert.setSubject([{ shortName: "CN", value: hostname }]);
    cert.setIssuer([
      { shortName: "CN", value: "Anything Analyzer CA" },
      { shortName: "O", value: "Anything Analyzer" },
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

    // Include CA cert in chain so mobile clients receive the full chain
    const leafPem = forge.pki.certificateToPem(cert);
    const caPem = forge.pki.certificateToPem(this.caCert!);
    return {
      key: forge.pki.privateKeyToPem(keys.privateKey),
      cert: leafPem + caPem,
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
