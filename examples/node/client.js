const http = require('http');
const https = require('https');

/**
 * Client Node.js de production pour la passerelle de chiffrement post-quantique.
 * Supporte HTTP/TCP et Unix Domain Socket (UDS) sans dépendance externe.
 */
class PQCryptoClient {
  constructor(options = 'http://127.0.0.1:8080') {
    if (typeof options === 'string') {
      this.baseURL = options.replace(/\/+$/, '');
      this.socketPath = null;
      this.timeout = 5000;
    } else if (options && typeof options === 'object') {
      this.baseURL = (options.baseURL || 'http://127.0.0.1:8080').replace(/\/+$/, '');
      this.socketPath = options.socketPath || null;
      this.timeout = typeof options.timeout === 'number' ? options.timeout : 5000;
    } else {
      throw new TypeError('Paramètre options invalide (doit être une URL ou un objet de configuration)');
    }
  }

  async call(endpoint, payload) {
    return new Promise((resolve, reject) => {
      const isHttps = this.baseURL.startsWith('https:');
      const transport = isHttps ? https : http;

      const reqOptions = {
        method: payload ? 'POST' : 'GET',
        headers: {
          'Accept': 'application/json',
          ...(payload ? { 'Content-Type': 'application/json; charset=utf-8' } : {}),
        },
        timeout: this.timeout,
      };

      if (this.socketPath) {
        reqOptions.socketPath = this.socketPath;
        reqOptions.path = endpoint;
      } else {
        const u = new URL(this.baseURL + endpoint);
        reqOptions.protocol = u.protocol;
        reqOptions.hostname = u.hostname;
        reqOptions.port = u.port || (isHttps ? 443 : 80);
        reqOptions.path = u.pathname + u.search;
      }

      const req = transport.request(reqOptions, (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          let data;
          try {
            data = JSON.parse(body);
          } catch (_) {
            return reject(new Error(`Réponse non-JSON reçue (HTTP ${res.statusCode}): ${body.slice(0, 200)}`));
          }

          if (res.statusCode < 200 || res.statusCode >= 300) {
            const msg = (data && (data.error || data.message)) || `HTTP ${res.statusCode}`;
            const err = new Error(msg);
            err.statusCode = res.statusCode;
            err.response = data;
            return reject(err);
          }

          resolve(data);
        });
      });

      req.on('timeout', () => {
        req.destroy(new Error(`Délai d'expiration réseau dépassé (${this.timeout}ms)`));
      });

      req.on('error', (err) => {
        reject(err);
      });

      if (payload) {
        req.write(JSON.stringify(payload));
      }
      req.end();
    });
  }

  async wrapKey(dek, recipientPK = null) {
    if (!dek || (typeof dek !== 'string' && !Buffer.isBuffer(dek))) {
      throw new TypeError('La clé symétrique DEK doit être un Buffer ou une chaîne non vide');
    }
    const key = Buffer.isBuffer(dek) ? dek.toString('base64') : dek;
    const res = await this.call('/wrap-key', {
      plaintext_key: key,
      recipient_public_key: recipientPK || undefined,
    });
    if (!res || typeof res.wrapped_key !== 'string') {
      throw new Error('Réponse /wrap-key invalide: champ wrapped_key manquant');
    }
    return res;
  }

  async unwrapKey(envelope) {
    if (!envelope || typeof envelope !== 'object') {
      throw new TypeError('Paramètre envelope invalide');
    }
    const res = await this.call('/unwrap-key', envelope);
    if (!res || typeof res.plaintext_key !== 'string') {
      throw new Error('Réponse /unwrap-key invalide: champ plaintext_key manquant');
    }
    const rawB64 = res.plaintext_key.trim();
    if (rawB64.length === 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(rawB64) || rawB64.length % 4 !== 0) {
      throw new Error('Réponse /unwrap-key invalide: encodage Base64 corrompu');
    }
    const buf = Buffer.from(rawB64, 'base64');
    if (buf.length < 16 || buf.length > 128) {
      throw new Error(`Longueur de clé déballée invalide (${buf.length} octets): doit être comprise entre 16 et 128 octets`);
    }
    return buf;
  }

  async encrypt(plaintext, recipientPK = null) {
    if (typeof plaintext !== 'string' || plaintext.length === 0) {
      throw new TypeError('Le texte en clair doit être une chaîne non vide');
    }
    return this.call('/encrypt', {
      plaintext,
      recipient_public_key: recipientPK || undefined,
    });
  }

  async decrypt(envelope) {
    if (!envelope || typeof envelope !== 'object') {
      throw new TypeError('Paramètre envelope invalide');
    }
    const res = await this.call('/decrypt', envelope);
    if (!res || typeof res.plaintext !== 'string') {
      throw new Error('Réponse /decrypt invalide: champ plaintext manquant');
    }
    return res.plaintext;
  }
}

module.exports = { PQCryptoClient };
module.exports.PQCryptoClient = PQCryptoClient;
module.exports.default = PQCryptoClient;
