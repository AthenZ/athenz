'use strict';

const functions = require('@google-cloud/functions-framework');
const http = require("http");
const https = require("https");
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

    // TODO: We probably want to get reed of "ztsRequestBody"...
    const ztsRequestBody = {
        domain: athenzDomain.toLowerCase(),
        service: athenzService.toLowerCase(),
        provider: athenzProvider.toLowerCase(),
    };

    // Get an identity-document for this GCF from GCP.
    ztsRequestBody.attestationData = await getGcpFunctionAttestationData(ztsUrl);
    console.log(`GCP Attestation Data: ${ztsRequestBody.attestationData}`);

    // Create a CSR (and a private-key).
    const { privateKey, csr } = await generateCsr(
        `${ztsRequestBody.domain}.${ztsRequestBody.service}`,
        certOrg,
        certOrgUnit,
        [
            `${ztsRequestBody.service}.${ztsRequestBody.domain.replace(/\./g, '-')}.${certDomain}`,
            `gcf-${gcpProjectId}-${ztsRequestBody.service}.instanceid.athenz.${certDomain}`,
            `spiffe://${ztsRequestBody.domain}/sa/${ztsRequestBody.service}`,
        ]);
    ztsRequestBody.csr = csr;

    console.log('CSR:\n', csr);
    console.log('Private Key:\n', privateKey
    );

    // Send CSR to ZTS.
    const ztsResponse = await getCredsFromZts(ztsUrl, ztsRequestBody);
    console.log(`ZTS response: ${JSON.stringify(ztsResponse, null, 4)}`);

    return ztsResponse.x509Certificate;
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
                let responseBodyChunks = [];
                res.on('data', (chunk) => {
                    responseBodyChunks.push(chunk);
                });
                res.on('end', () => {
                    // Response is read successfully.
                    const responseBody = responseBodyChunks.join('');
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


// Send CSR to ZTS.
function getCredsFromZts(ztsUrl, ztsRequestBody) {
    return new Promise((resolve, reject) => {
        const requestUrl = `${ztsUrl}/instance`;
        const request = https.request(
            requestUrl,
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            },
            (response) => {
                response.setEncoding('utf8');

                const responseBodyChunks = [];
                response.on('data', (chunk) => {
                    responseBodyChunks.push(chunk);
                });

                response.on('end', () => {
                    // Response is read successfully.
                    const responseBody = responseBodyChunks.join('');
                    if (response.statusCode !== 200) {
                        // Bad HTTP status code.
                        reject(new Error(`HTTP request to    ${requestUrl}    returned ${response.statusCode} (${response.status}). Body:\n${responseBody}`));
                    } else {
                        // Parse response.
                        try {
                            const response = JSON.parse(responseBody);
                            resolve(response);
                        } catch (error) {
                            reject(new Error(`HTTP request to    ${requestUrl}    returned non-JSON response. Body:\n${responseBody}`));
                        }
                    }
                });
            });
        request.on('error', (error) => {
            reject(new Error(`Failed to make HTTP request to    ${requestUrl}    : ${error}`));
        });
        request.write(JSON.stringify(ztsRequestBody));
        request.end()
    });
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