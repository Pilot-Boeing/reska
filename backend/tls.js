/**
 * tls.js — самоподписанный TLS-сертификат (автогенерация при первом запуске).
 * Хранится в certs/ (ключ 0600). Срок — 1 год.
 */
const fs = require('fs');
const path = require('path');
const selfsigned = require('selfsigned');

const CERT_DIR = path.join(__dirname, '..', 'certs');
const KEY_PATH = path.join(CERT_DIR, 'key.pem');
const CERT_PATH = path.join(CERT_DIR, 'cert.pem');

async function ensureTls() {
  if (fs.existsSync(KEY_PATH) && fs.existsSync(CERT_PATH)) {
    return {
      key: fs.readFileSync(KEY_PATH),
      cert: fs.readFileSync(CERT_PATH)
    };
  }
  if (!fs.existsSync(CERT_DIR)) fs.mkdirSync(CERT_DIR, { recursive: true });

  const pems = await selfsigned.generate(
    [
      { name: 'commonName', value: 'localhost' },
      { name: 'organizationName', value: 'РЕСКА' }
    ],
    {
      days: 365,
      keySize: 2048,
      algorithm: 'sha256',
      extensions: [
        { name: 'subjectAltName', altNames: [
          { type: 2, value: 'localhost' },
          { type: 7, ip: '127.0.0.1' },
          { type: 7, ip: '::1' }
        ] }
      ]
    }
  );
  const key = Buffer.from(pems.private);
  const cert = Buffer.from(pems.cert);
  fs.writeFileSync(KEY_PATH, key);
  fs.writeFileSync(CERT_PATH, cert);
  if (process.platform !== 'win32') fs.chmodSync(KEY_PATH, 0o600);
  console.log('Сгенерирован самоподписанный TLS-сертификат (certs/).');
  return { key, cert };
}

module.exports = { ensureTls };
