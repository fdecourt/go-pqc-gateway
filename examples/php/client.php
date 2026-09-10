<?php
declare(strict_types=1);

/**
 * Client PHP de production pour la passerelle de chiffrement post-quantique.
 * Supporte les connexions HTTP/TCP et Unix Domain Socket (UDS).
 */
class PQCryptoClient {
    private string $baseUrl;
    private ?string $socketPath;
    private int $timeout;

    public function __construct(string $baseUrl = 'http://127.0.0.1:8080', ?string $socketPath = null, int $timeout = 5) {
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->socketPath = $socketPath;
        $this->timeout = $timeout;
    }

    public function call(string $endpoint, ?array $payload = null): array {
        $ch = curl_init($this->baseUrl . $endpoint);
        if ($ch === false) {
            throw new RuntimeException("Échec de l'initialisation de la session cURL");
        }

        $headers = ['Accept: application/json'];
        $options = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_CONNECTTIMEOUT => 2,
        ];

        if ($this->socketPath !== null && $this->socketPath !== '') {
            $options[CURLOPT_UNIX_SOCKET_PATH] = $this->socketPath;
        }

        if ($payload !== null) {
            $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
            if ($json === false) {
                curl_close($ch);
                throw new InvalidArgumentException("Erreur d'encodage JSON: " . json_last_error_msg());
            }
            $headers[] = 'Content-Type: application/json; charset=utf-8';
            $options[CURLOPT_POST] = true;
            $options[CURLOPT_POSTFIELDS] = $json;
        }

        $options[CURLOPT_HTTPHEADER] = $headers;
        curl_setopt_array($ch, $options);

        $raw = curl_exec($ch);
        if ($raw === false) {
            $errNo = curl_errno($ch);
            $errMsg = curl_error($ch);
            curl_close($ch);
            throw new RuntimeException("Erreur de transport réseau cURL ($errNo): $errMsg");
        }

        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $data = json_decode((string)$raw, true);
        if (!is_array($data)) {
            throw new RuntimeException("Réponse serveur non-JSON invalide (HTTP $code): " . substr((string)$raw, 0, 200));
        }

        if ($code < 200 || $code >= 300) {
            $msg = $data['error'] ?? $data['message'] ?? "Erreur HTTP $code";
            throw new RuntimeException((string)$msg, $code);
        }

        return $data;
    }

    public function wrapKey(string $dek, ?string $recipientPK = null): array {
        if ($dek === '') {
            throw new InvalidArgumentException("La clé symétrique DEK ne peut pas être vide");
        }
        $payload = ['plaintext_key' => base64_encode($dek)];
        if ($recipientPK !== null && $recipientPK !== '') {
            $payload['recipient_public_key'] = $recipientPK;
        }
        $res = $this->call('/wrap-key', $payload);
        if (empty($res['wrapped_key']) || !is_string($res['wrapped_key'])) {
            throw new RuntimeException("Réponse /wrap-key invalide: champ wrapped_key manquant");
        }
        return $res;
    }

    public function unwrapKey(array $envelope): string {
        $required = ['encapsulated_key', 'nonce', 'wrapped_key'];
        foreach ($required as $field) {
            if (empty($envelope[$field]) || !is_string($envelope[$field])) {
                throw new InvalidArgumentException("Enveloppe incomplète: champ '$field' manquant ou invalide");
            }
        }
        $res = $this->call('/unwrap-key', $envelope);
        if (empty($res['plaintext_key']) || !is_string($res['plaintext_key'])) {
            throw new RuntimeException("Réponse /unwrap-key invalide: champ plaintext_key manquant");
        }
        $rawB64 = trim($res['plaintext_key']);
        if ($rawB64 === '' || !preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $rawB64) || strlen($rawB64) % 4 !== 0) {
            throw new RuntimeException("Réponse /unwrap-key invalide: encodage Base64 corrompu");
        }
        $key = base64_decode($rawB64, true);
        if ($key === false || strlen($key) < 16 || strlen($key) > 128) {
            throw new RuntimeException("Longueur de clé déballée invalide (" . strlen((string)$key) . " octets): doit être comprise entre 16 et 128 octets");
        }
        return $key;
    }

    public function encrypt(string $plaintext, ?string $recipientPK = null): array {
        if ($plaintext === '') {
            throw new InvalidArgumentException("Le texte en clair ne peut pas être vide");
        }
        $payload = ['plaintext' => $plaintext];
        if ($recipientPK !== null && $recipientPK !== '') {
            $payload['recipient_public_key'] = $recipientPK;
        }
        return $this->call('/encrypt', $payload);
    }

    public function decrypt(array $envelope): string {
        $res = $this->call('/decrypt', $envelope);
        if (!isset($res['plaintext']) || !is_string($res['plaintext'])) {
            throw new RuntimeException("Réponse /decrypt invalide: champ plaintext manquant");
        }
        return $res['plaintext'];
    }
}
