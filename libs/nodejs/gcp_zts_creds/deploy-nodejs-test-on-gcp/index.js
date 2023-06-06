'use strict';

const functions = require('@google-cloud/functions-framework');
const http = require("http");
const pem = require('pem');

// See https://cloud.google.com/functions/docs/writing/write-http-functions#http-example-nodejs

async function getSiaCertsDemo() {
    // Read configurations.
    const athenzDomain = getMandatoryEnvVar("ATHENZ_DOMAIN");
    const athenzService = getMandatoryEnvVar("ATHENZ_SERVICE");
    const gcpProjectId = getMandatoryEnvVar("GCP_PROJECT_ID");
    const gcpRegion = getMandatoryEnvVar("GCP_REGION");
    const athenzProvider = "sys.gcp." + gcpRegion;
    const ztsUrl = getMandatoryEnvVar("ZTS_URL");
    const certOrgUnit = "Athenz"; // the dn you want included in cert - should not change
    const certOrg = "Oath"; // the dn you want included in cert - should not change
    const certDomain = "gcp.yahoo.cloud"; // do not change

    const attestationData = await getGcpFunctionAttestationData(ztsUrl);
    console.log(`GCP Attestation Data: ${attestationData}`);

    // const privateKey = await generateRSAPrivateKey();
    // console.log(`Private key constructor: `, privateKey.constructor.name);
    // console.log(`Private key: `, privateKey);
    // console.log(`Private key export: `, privateKey.export({ type: 'pkcs1', format: 'pem' }));

    // TODO: We probably want to get reed of "info"...
    const info = {
        domain: athenzDomain.toLowerCase(),
        service: athenzService.toLowerCase(),
        provider: athenzProvider.toLowerCase(),
    };

    // Create a CSR (and a private-key).
    const { privateKey, csr } = await generateCsr(
        `${info.domain}.${info.service}`,
        certOrg,
        certOrgUnit,
        [
            `${info.service}.${info.domain.replace(/\./g, '-')}.${certDomain}`,
            `gcf-${gcpProjectId}-${info.service}.instanceid.athenz.${certDomain}`,
            `spiffe://${info.domain}/sa/${info.service}`,
        ]);

    console.log('CSR:\n', csr);
    console.log('Private Key:\n', privateKey);


    return "<<<CERT>>>";
}

// Get an identity-document for this GCF from GCP.
function getGcpFunctionAttestationData(ztsUrl) {
    return new Promise((resolve, reject) => {
        const gcpIdentityUrl = `http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience=${ztsUrl}&format=full`;
        console.log(`Getting GCF identity from: ${gcpIdentityUrl}`);
        http.get(
            gcpIdentityUrl,
            {
                headers: {
                    'Metadata-Flavor': 'Google',
                },
            },
            (res) => {
                // Read response body.
                res.setEncoding('utf8');
                let responseBody = '';
                res.on('data', (chunk) => {
                    responseBody += chunk;
                });
                res.on('end', () => {
                    // Response is read successfully.
                    if (res.statusCode !== 200) {
                        // Bad HTTP status code.
                        reject(new Error(`HTTP request to    ${gcpIdentityUrl}    returned ${res.statusCode} (${res.status}). Body:\n${responseBody}`));
                    } else {
                        // Success.
                        resolve(`{"identityToken":"${responseBody}"}`);
                    }
                });
            }
        ).on('error', (error) => {
            reject(new Error(`Failed to make HTTP request to    ${gcpIdentityUrl}    : ${error}`));
        });
    });
}

// Generate a CSR.
function generateCsr(commonName, organization, organizationalUnit, altNames) {
    return new Promise((resolve, reject) =>
        pem.createCSR(
            {
                commonName,
                organization,
                organizationalUnit,
                altNames,
                keyBitSize: 2048
            },
            (err, keys) => {
                if (err) {
                    return reject(err);
                } else {
                    resolve(
                        {
                            privateKey: keys.clientKey,
                            csr: keys.csr,
                        })
                }
            }));
}




// Register an HTTP function with the Functions Framework
functions.http('GcfSiaTest', async (req, res) => {
    res.send(await executeAsyncWhileCapturingLogs(getSiaCertsDemo));
});

async function executeAsyncWhileCapturingLogs(work) {
    const allLogs = [];

    // Override all console methods, to ALSO save all logs into allLogs.
    const origConsole = { ...console };
    const consoleLogMethods = [ 'error', 'warn', 'info', 'debug', 'log', 'group', 'groupCollapsed' ];
    for (const consoleLogMethod of consoleLogMethods) {
        console[consoleLogMethod] = function() {
            allLogs.push(Array.prototype.join.call(arguments, ' '));
            return origConsole[consoleLogMethod].apply(this, arguments);
        };
    }

    try {
        await work();
    } catch (error) {
        if (error && error.stack) {
            console.error(error.stack);
        } else {
            console.error('ERROR: ', error);
        }
    } finally {
        // Restore console methods.
        for (const consoleLogMethod of consoleLogMethods) {
            console[consoleLogMethod] = origConsole[consoleLogMethod];
        }
    }

    return allLogs.join('\n');
}

function getMandatoryEnvVar(envVar) {
    const value = process.env[envVar];
    if (value === undefined) {
        throw new Error(`Mandatory environment-variable \"${envVar}\" is not defined`);
    }
    if (! value) {
        throw new Error(`Mandatory environment-variable \"${envVar}\" is defined but is empty`);
    }
    console.log(`Environment variable:   ${envVar} = \"${value}\"`);
    return value;
}
