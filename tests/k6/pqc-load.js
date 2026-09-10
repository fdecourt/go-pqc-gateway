import http from 'k6/http';
import { check, fail } from 'k6';
import { Trend, Rate } from 'k6/metrics';
import encoding from 'k6/encoding';
import crypto from 'k6/crypto';

// ============================================================================
// CONFIGURATION
// ============================================================================

const BASE = __ENV.BASE || 'http://127.0.0.1:8085';
const TEST = (__ENV.TEST || 'kem_encap').toLowerCase();

const LARGE_MB = Number(__ENV.LARGE_MB || 5);
const LARGE_BYTES = LARGE_MB * 1024 * 1024;

// Tests disponibles :
//
// health
// kem_encap
// kem_rt
// json_rt
// wrap_rt
// binary_rt
// json_large_rt
// binary_large_rt
// mixed
//
// Exemples :
// k6 run --vus 16 --duration 30s -e TEST=kem_encap pqc-load.js
// k6 run --vus 16 --duration 30s -e TEST=kem_rt pqc-load.js
// k6 run --vus 8  --duration 30s -e TEST=mixed pqc-load.js
// k6 run --vus 4  --duration 30s -e TEST=binary_large_rt pqc-load.js

export const options = {
    vus: Number(__ENV.VUS || 1),
    duration: __ENV.DURATION || '30s',

    summaryTrendStats: [
        'avg',
        'min',
        'med',
        'p(90)',
        'p(95)',
        'p(99)',
        'max',
    ],

    thresholds: {
        http_req_failed: ['rate<0.000001'],
        pqc_functional_error: ['rate<0.000001'],
    },
};

// ============================================================================
// MÉTRIQUES PERSONNALISÉES
// ============================================================================

// KEM
const kemEncapMs = new Trend('kem_encap_ms', true);
const kemDecapMs = new Trend('kem_decap_ms', true);
const kemRoundTripMs = new Trend('kem_roundtrip_ms', true);

// JSON
const jsonEncryptMs = new Trend('json_encrypt_ms', true);
const jsonDecryptMs = new Trend('json_decrypt_ms', true);
const jsonRoundTripMs = new Trend('json_roundtrip_ms', true);

// Wrap / Unwrap
const wrapMs = new Trend('wrap_ms', true);
const unwrapMs = new Trend('unwrap_ms', true);
const wrapRoundTripMs = new Trend('wrap_roundtrip_ms', true);

// Binaire
const binaryEncryptMs = new Trend('binary_encrypt_ms', true);
const binaryDecryptMs = new Trend('binary_decrypt_ms', true);
const binaryRoundTripMs = new Trend('binary_roundtrip_ms', true);

// Erreurs fonctionnelles
const functionalError = new Rate('pqc_functional_error');

// ============================================================================
// DONNÉES DE TEST
// ============================================================================

function makeBinary(size) {
    const data = new Uint8Array(size);

    // Pattern déterministe, suffisamment bon pour un benchmark de transport.
    for (let i = 0; i < size; i++) {
        data[i] = (17 + i * 31) & 0xff;
    }

    return data.buffer;
}

const SHORT_BINARY = makeBinary(72);

// Générés uniquement lorsque ces scénarios sont demandés.
// Évite de multiplier inutilement 5 MiB par VU pour les tests KEM.
const LARGE_BINARY =
    TEST === 'binary_large_rt'
        ? makeBinary(LARGE_BYTES)
        : null;

const LARGE_TEXT =
    TEST === 'json_large_rt'
        ? 'P'.repeat(LARGE_BYTES)
        : null;

// Une DEK par runtime/VU suffit pour benchmarker le wrapping.
// On ne cherche pas ici à benchmarker le RNG de k6.
const DEK = crypto.randomBytes(32);
const DEK_B64 = encoding.b64encode(DEK, 'std');

// ============================================================================
// HELPERS
// ============================================================================

const JSON_HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
};

const BINARY_HEADERS = {
    'Content-Type': 'application/octet-stream',
    'Accept': 'application/octet-stream',
};

function postJson(path, payload, name) {
    return http.post(
        `${BASE}${path}`,
        JSON.stringify(payload),
        {
            headers: JSON_HEADERS,
            tags: {
                endpoint: name,
                test: TEST,
            },
        }
    );
}

function postBinary(path, payload, name) {
    return http.post(
        `${BASE}${path}`,
        payload,
        {
            headers: BINARY_HEADERS,

            // CRITIQUE :
            // sans responseType=binary, k6 convertit le body en texte.
            responseType: 'binary',

            tags: {
                endpoint: name,
                test: TEST,
            },
        }
    );
}

function status200(response, name) {
    return check(response, {
        [`${name} HTTP 200`]: (r) => r.status === 200,
    });
}

function safeJson(response) {
    try {
        return response.json();
    } catch (_) {
        return null;
    }
}

function equalBuffers(a, b) {
    if (!(a instanceof ArrayBuffer) || !(b instanceof ArrayBuffer)) {
        return false;
    }

    const aa = new Uint8Array(a);
    const bb = new Uint8Array(b);

    if (aa.length !== bb.length) {
        return false;
    }

    for (let i = 0; i < aa.length; i++) {
        if (aa[i] !== bb[i]) {
            return false;
        }
    }

    return true;
}

function recordFunctional(valid) {
    functionalError.add(!valid);
    return valid;
}

// ============================================================================
// HEALTH
// ============================================================================

export function health() {
    const response = http.get(
        `${BASE}/health`,
        {
            tags: {
                endpoint: 'health',
                test: TEST,
            },
        }
    );

    const valid = check(response, {
        'health HTTP 200': (r) => r.status === 200,
        'service healthy': (r) => {
            const body = safeJson(r);
            return body !== null && body.status === 'healthy';
        },
    });

    recordFunctional(valid);
}

// ============================================================================
// KEM ENCAPSULATION SEULE
//
// C'est LE test à utiliser pour connaître le débit maximal brut de
// /kem/encapsulate.
// Une itération = UNE requête HTTP.
// ============================================================================

export function kemEncapOnly() {
    const response = postJson(
        '/kem/encapsulate',
        {},
        'kem_encapsulate'
    );

    kemEncapMs.add(response.timings.duration);

    const valid = check(response, {
        'KEM encapsulate HTTP 200': (r) => r.status === 200,

        'KEM encapsulated_key présent': (r) => {
            const body = safeJson(r);
            return body !== null &&
                typeof body.encapsulated_key === 'string' &&
                body.encapsulated_key.length > 0;
        },

        'KEM shared_secret présent': (r) => {
            const body = safeJson(r);
            return body !== null &&
                typeof body.shared_secret === 'string' &&
                body.shared_secret.length > 0;
        },
    });

    recordFunctional(valid);
}

// ============================================================================
// KEM ROUND-TRIP
//
// Encapsulate -> Decapsulate -> comparaison des secrets.
// Une itération = DEUX requêtes HTTP.
// ============================================================================

export function kemRoundTrip() {
    const enc = postJson(
        '/kem/encapsulate',
        {},
        'kem_encapsulate'
    );

    kemEncapMs.add(enc.timings.duration);

    if (!status200(enc, 'KEM encapsulate')) {
        recordFunctional(false);
        return;
    }

    const encBody = safeJson(enc);

    if (
        encBody === null ||
        !encBody.encapsulated_key ||
        !encBody.shared_secret
    ) {
        recordFunctional(false);
        return;
    }

    const dec = postJson(
        '/kem/decapsulate',
        {
            encapsulated_key: encBody.encapsulated_key,
        },
        'kem_decapsulate'
    );

    kemDecapMs.add(dec.timings.duration);

    const roundTrip =
        enc.timings.duration +
        dec.timings.duration;

    kemRoundTripMs.add(roundTrip);

    const valid = check(dec, {
        'KEM decapsulate HTTP 200': (r) => r.status === 200,

        'KEM secret identique': (r) => {
            const body = safeJson(r);

            return body !== null &&
                body.shared_secret === encBody.shared_secret;
        },
    });

    recordFunctional(valid);
}

// ============================================================================
// JSON ENCRYPT / DECRYPT
// ============================================================================

export function jsonRoundTrip() {
    // Payload différent à chaque itération sans RNG coûteux.
    const plaintext =
        `PQC-k6-VU-${__VU}-ITER-${__ITER}-` +
        '0123456789ABCDEF0123456789ABCDEF';

    const enc = postJson(
        '/encrypt',
        {
            plaintext: plaintext,
        },
        'json_encrypt'
    );

    jsonEncryptMs.add(enc.timings.duration);

    if (!status200(enc, 'JSON encrypt')) {
        recordFunctional(false);
        return;
    }

    const e = safeJson(enc);

    if (
        e === null ||
        !e.algorithm ||
        !e.version ||
        !e.suite_id ||
        !e.encapsulated_key ||
        !e.nonce ||
        !e.ciphertext
    ) {
        recordFunctional(false);
        return;
    }

    const dec = postJson(
        '/decrypt',
        {
            algorithm: e.algorithm,
            version: e.version,
            suite_id: e.suite_id,
            encapsulated_key: e.encapsulated_key,
            nonce: e.nonce,
            ciphertext: e.ciphertext,
        },
        'json_decrypt'
    );

    jsonDecryptMs.add(dec.timings.duration);

    jsonRoundTripMs.add(
        enc.timings.duration +
        dec.timings.duration
    );

    const valid = check(dec, {
        'JSON decrypt HTTP 200': (r) => r.status === 200,

        'JSON plaintext identique': (r) => {
            const d = safeJson(r);

            return d !== null &&
                d.plaintext === plaintext;
        },
    });

    recordFunctional(valid);
}

// ============================================================================
// WRAP / UNWRAP DEK AES-256
// ============================================================================

export function wrapRoundTrip() {
    const enc = postJson(
        '/wrap-key',
        {
            plaintext_key: DEK_B64,
        },
        'wrap_key'
    );

    wrapMs.add(enc.timings.duration);

    if (!status200(enc, 'wrap-key')) {
        recordFunctional(false);
        return;
    }

    const e = safeJson(enc);

    if (
        e === null ||
        !e.algorithm ||
        !e.version ||
        !e.suite_id ||
        !e.encapsulated_key ||
        !e.nonce ||
        !e.wrapped_key
    ) {
        recordFunctional(false);
        return;
    }

    const dec = postJson(
        '/unwrap-key',
        {
            algorithm: e.algorithm,
            version: e.version,
            suite_id: e.suite_id,
            encapsulated_key: e.encapsulated_key,
            nonce: e.nonce,
            wrapped_key: e.wrapped_key,
        },
        'unwrap_key'
    );

    unwrapMs.add(dec.timings.duration);

    wrapRoundTripMs.add(
        enc.timings.duration +
        dec.timings.duration
    );

    const valid = check(dec, {
        'unwrap-key HTTP 200': (r) => r.status === 200,

        'DEK identique': (r) => {
            const body = safeJson(r);

            return body !== null &&
                body.plaintext_key === DEK_B64;
        },
    });

    recordFunctional(valid);
}

// ============================================================================
// BINAIRE COURT
// ============================================================================

export function binaryRoundTrip() {
    binaryRoundTripWithPayload(
        SHORT_BINARY,
        'binary_short'
    );
}

// ============================================================================
// BINAIRE LARGE
// ============================================================================

export function binaryLargeRoundTrip() {
    if (LARGE_BINARY === null) {
        fail(
            'LARGE_BINARY non initialisé. ' +
            'Lance avec -e TEST=binary_large_rt'
        );
    }

    binaryRoundTripWithPayload(
        LARGE_BINARY,
        'binary_large'
    );
}

function binaryRoundTripWithPayload(payload, tag) {
    const enc = postBinary(
        '/encrypt',
        payload,
        `${tag}_encrypt`
    );

    binaryEncryptMs.add(
        enc.timings.duration,
        { payload: tag }
    );

    if (!status200(enc, `${tag} encrypt`)) {
        recordFunctional(false);
        return;
    }

    if (!(enc.body instanceof ArrayBuffer)) {
        recordFunctional(false);
        return;
    }

    const dec = postBinary(
        '/decrypt',
        enc.body,
        `${tag}_decrypt`
    );

    binaryDecryptMs.add(
        dec.timings.duration,
        { payload: tag }
    );

    binaryRoundTripMs.add(
        enc.timings.duration +
        dec.timings.duration,
        { payload: tag }
    );

    const valid = check(dec, {
        [`${tag} decrypt HTTP 200`]:
            (r) => r.status === 200,

        [`${tag} plaintext identique`]:
            (r) => equalBuffers(payload, r.body),
    });

    recordFunctional(valid);
}

// ============================================================================
// JSON LARGE
// ============================================================================

export function jsonLargeRoundTrip() {
    if (LARGE_TEXT === null) {
        fail(
            'LARGE_TEXT non initialisé. ' +
            'Lance avec -e TEST=json_large_rt'
        );
    }

    const enc = postJson(
        '/encrypt',
        {
            plaintext: LARGE_TEXT,
        },
        'json_large_encrypt'
    );

    jsonEncryptMs.add(
        enc.timings.duration,
        { payload: 'large' }
    );

    if (!status200(enc, 'JSON large encrypt')) {
        recordFunctional(false);
        return;
    }

    const e = safeJson(enc);

    if (e === null || !e.ciphertext) {
        recordFunctional(false);
        return;
    }

    const dec = postJson(
        '/decrypt',
        {
            algorithm: e.algorithm,
            version: e.version,
            suite_id: e.suite_id,
            encapsulated_key: e.encapsulated_key,
            nonce: e.nonce,
            ciphertext: e.ciphertext,
        },
        'json_large_decrypt'
    );

    jsonDecryptMs.add(
        dec.timings.duration,
        { payload: 'large' }
    );

    jsonRoundTripMs.add(
        enc.timings.duration +
        dec.timings.duration,
        { payload: 'large' }
    );

    const valid = check(dec, {
        'JSON large decrypt HTTP 200':
            (r) => r.status === 200,

        'JSON large plaintext identique':
            (r) => {
                const body = safeJson(r);

                return body !== null &&
                    body.plaintext === LARGE_TEXT;
            },
    });

    recordFunctional(valid);
}

// ============================================================================
// MIXED
//
// Charge plus réaliste.
//
// Chaque VU alterne :
// 25 % KEM
// 25 % encrypt/decrypt JSON
// 25 % wrap/unwrap DEK
// 25 % binaire court
//
// On ne mélange PAS les gros 5 MiB ici.
// ============================================================================

export function mixedWorkload() {
    const choice = (__ITER + __VU) % 4;

    switch (choice) {
        case 0:
            kemRoundTrip();
            break;

        case 1:
            jsonRoundTrip();
            break;

        case 2:
            wrapRoundTrip();
            break;

        case 3:
            binaryRoundTrip();
            break;
    }
}

// ============================================================================
// SETUP
// ============================================================================

export function setup() {
    const response = http.get(
        `${BASE}/health`,
        {
            tags: {
                endpoint: 'setup_health',
            },
        }
    );

    if (response.status !== 200) {
        fail(
            `Gateway inaccessible : HTTP ${response.status}`
        );
    }

    const body = safeJson(response);

    console.log('');
    console.log('========================================');
    console.log(' PQC GATEWAY - K6 LOAD TEST');
    console.log('========================================');
    console.log(`Gateway : ${BASE}`);
    console.log(`Test    : ${TEST}`);

    if (body !== null) {
        console.log(`Status  : ${body.status}`);
        console.log(`Algo    : ${body.algorithm}`);
    }

    if (
        TEST === 'binary_large_rt' ||
        TEST === 'json_large_rt'
    ) {
        console.log(`Payload : ${LARGE_MB} MiB`);
    }

    console.log('========================================');
    console.log('');
}

// ============================================================================
// DISPATCHER
// ============================================================================

export default function () {
    switch (TEST) {
        case 'health':
            health();
            return;

        case 'kem_encap':
            kemEncapOnly();
            return;

        case 'kem_rt':
            kemRoundTrip();
            return;

        case 'json_rt':
            jsonRoundTrip();
            return;

        case 'wrap_rt':
            wrapRoundTrip();
            return;

        case 'binary_rt':
            binaryRoundTrip();
            return;

        case 'json_large_rt':
            jsonLargeRoundTrip();
            return;

        case 'binary_large_rt':
            binaryLargeRoundTrip();
            return;

        case 'mixed':
            mixedWorkload();
            return;

        default:
            fail(
                `TEST inconnu : "${TEST}". ` +
                'Valeurs : health, kem_encap, kem_rt, json_rt, ' +
                'wrap_rt, binary_rt, json_large_rt, ' +
                'binary_large_rt, mixed'
            );
    }
}