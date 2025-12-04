/*instrumentation.mjs*/
import { NodeSDK } from '@opentelemetry/sdk-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-grpc';
import { OTLPLogExporter } from '@opentelemetry/exporter-logs-otlp-grpc';
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-grpc';
import { BatchLogRecordProcessor } from '@opentelemetry/sdk-logs';
import { PeriodicExportingMetricReader } from '@opentelemetry/sdk-metrics';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { credentials } from '@grpc/grpc-js';
import { readFileSync } from 'fs';
import { RuntimeNodeInstrumentation } from '@opentelemetry/instrumentation-runtime-node';
import { Resource } from '@opentelemetry/resources';
import { SemanticResourceAttributes } from '@opentelemetry/semantic-conventions';

const STATIC_ASSET_EXTENSIONS = ['.js', '.css', '.svg', '.js.map', '.webp'];

const ignoreStaticAssets = (request = {}) => {
    const url = request.url?.toLowerCase?.() || '';
    return STATIC_ASSET_EXTENSIONS.some(ext => url.endsWith(ext));
};

const updateSpanName = (span, request = {}) => {
    const rawUrl = request.url || '';
    const path = rawUrl.split('?')[0] || '/';
    const method = request.method || 'UNKNOWN';
    span.updateName(`${method} ${path}`);
};


// Setup gRPC credentials with TLS
let grpcCredentials = credentials.createInsecure();
let exporterOptions = { credentials: grpcCredentials };
const allowInsecureFallback =
    process.env.OTEL_ALLOW_INSECURE_FALLBACK === 'true';

if (process.env.OTEL_EXPORTER_OTLP_CA_CERTIFICATE) {
    try {
        const caCert = readFileSync(process.env.OTEL_EXPORTER_OTLP_CA_CERTIFICATE);
        grpcCredentials = credentials.createSsl(caCert);
        exporterOptions = { credentials: grpcCredentials };
    } catch (err) {
        console.error('[OTEL] Failed to read CA certificate:', err.message);
        if (allowInsecureFallback) {
            console.warn(
                '[OTEL] OTEL_ALLOW_INSECURE_FALLBACK=true, falling back to insecure OTLP connection'
            );
            grpcCredentials = credentials.createInsecure();
            exporterOptions = { credentials: grpcCredentials };
        } else {
            console.error(
                '[OTEL] Insecure fallback is not allowed. Shutting down.'
            );
            throw err;
        }
    }
}

// Initialize OpenTelemetry SDK
const sdk = new NodeSDK({

    resource: new Resource({
        [SemanticResourceAttributes.SERVICE_NAME]: 'athenz-ui',
        [SemanticResourceAttributes.SERVICE_NAMESPACE]: 'AthenzUI',
        [SemanticResourceAttributes.DEPLOYMENT_ENVIRONMENT]:
            process.env.ENVIRONMENT || 'local',
    }),

    traceExporter: new OTLPTraceExporter(exporterOptions),
    logRecordProcessor: new BatchLogRecordProcessor(
        new OTLPLogExporter(exporterOptions)
    ),
    metricReader: new PeriodicExportingMetricReader({
        exporter: new OTLPMetricExporter(exporterOptions),
        exportIntervalMillis: 60000,
    }),
    instrumentations: [getNodeAutoInstrumentations({
        '@opentelemetry/instrumentation-aws-sdk': { enabled: false },
        '@opentelemetry/instrumentation-http': {
            enabled: true,
            // Ignore static assets like JS/CSS so dashboards focus on real endpoints
            ignoreIncomingRequestHook: ignoreStaticAssets,
            // Improve span names for better traces / metrics labels
            requestHook: (span, request) => {
                updateSpanName(span, request);
            },
        }
    }),
        new RuntimeNodeInstrumentation({
            enabled: true,
            exportFloats: true,
            memory: { enabled: true },
            cpu: { enabled: true },
            eventLoop: { enabled: true },
        })],
});

// -----------------------------
// Start + graceful shutdown
// -----------------------------

try {
    sdk.start();
    console.log('[OTEL] OpenTelemetry initialized');
} catch (err) {
    console.error('[OTEL] Failed to start OpenTelemetry SDK:', err.message);
    process.exit(1);
}

const gracefulShutdown = () => {
    console.log('[OTEL] Shutting down OpenTelemetry SDK...');
    sdk.shutdown()
        .then(() => {
            console.log('[OTEL] SDK shut down successfully');
            process.exit(0);
        })
        .catch((error) => {
            console.error('[OTEL] Error shutting down SDK', error);
            process.exit(1);
        });
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);
