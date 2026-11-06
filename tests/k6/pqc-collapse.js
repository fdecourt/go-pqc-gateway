import http from 'k6/http';
import { check } from 'k6';
import { Rate } from 'k6/metrics';

const BASE = __ENV.BASE || 'http://127.0.0.1:8085';

const functionalErrors = new Rate('pqc_functional_error');

export const options = {
    scenarios: {
        collapse: {
            executor: 'ramping-arrival-rate',

            // Départ tranquille
            startRate: 5000,
            timeUnit: '1s',

            // Pré-allocation côté k6
            preAllocatedVUs: 256,

            // Autorise k6 à augmenter fortement la concurrence
            // si le serveur commence à ralentir.
            maxVUs: 2000,

            stages: [
                // Mise en température
                { target: 5000, duration: '30s' },

                // Charge croissante
                { target: 10000, duration: '30s' },
                { target: 15000, duration: '30s' },
                { target: 18000, duration: '30s' },

                // Zone de ton plafond actuel
                { target: 20000, duration: '30s' },
                { target: 22000, duration: '30s' },

                // Surcharge
                { target: 25000, duration: '30s' },
                { target: 30000, duration: '30s' },

                // On relâche brutalement pour tester la récupération
                { target: 5000, duration: '5s' },
                { target: 5000, duration: '30s' },

                // Fin
                { target: 0, duration: '10s' },
            ],
        },
    },

    summaryTrendStats: [
        'avg',
        'min',
        'med',
        'p(90)',
        'p(95)',
        'p(99)',
        'max',
    ],

    // Ici je NE mets volontairement PAS abortOnFail.
    // Le but est justement d'observer ce qui se passe après le seuil.
    thresholds: {
        http_req_failed: ['rate<0.05'],
    },
};

export default function () {
    const r = http.post(
        `${BASE}/kem/encapsulate`,
        '{}',
        {
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },

            // Si une requête reste bloquée trop longtemps,
            // on préfère considérer qu'elle a échoué.
            timeout: '5s',

            tags: {
                endpoint: 'kem_encapsulate',
                test: 'collapse',
            },
        }
    );

    const ok = check(r, {
        'HTTP 200': (res) => res.status === 200,
    });

    functionalErrors.add(!ok);
}