'use strict';

const functions = require('@google-cloud/functions-framework');
const http = require("http");
const https = require("https");
const pem = require('pem');

// See https://cloud.google.com/functions/docs/writing/write-http-functions#http-example-nodejs

async function getSiaCertsDemo(
        athenzDomain,
        athenzService,
        gcpProjectId,
        gcpRegion,
        athenzProvider,
        ztsUrl,
        certDomain,
        optionalCountry,
        optionalState,
        optionalLocality,
        optionalOrganization,
        optionalOrganizationUnit) {

    athenzDomain   = athenzDomain.toLowerCase();
    athenzService  = athenzService.toLowerCase();
    athenzProvider = athenzProvider.toLowerCase();

    // Get an identity-document for this GCF from GCP.
    const attestationData = await getGcpFunctionAttestationData(ztsUrl);
    // console.log(`GCP Attestation Data: ${attestationData}`);  // commented out - sensitive info

    // Create a CSR (and a private-key).
    const { privateKey, csr } = await generateCsr(
        `${athenzDomain}.${athenzService}`,
        {
            country: optionalCountry,
            state: optionalState,
            locality: optionalLocality,
            organization: optionalOrganization,
            organizationUnit: optionalOrganizationUnit,
        },
        [
            `${athenzService}.${athenzDomain.replace(/\./g, '-')}.${certDomain}`,
            `gcf-${gcpProjectId}-${athenzService}.instanceid.athenz.${certDomain}`,
            `spiffe://${athenzDomain}/sa/${athenzService}`,
        ]);

    // console.log(`CSR to send to ZTS:\n${csr}`);
    // console.log('Private Key:\n', privateKey);

    // Send CSR to ZTS.
    const ztsResponse = await getCredsFromZts(
        ztsUrl,
        {
            domain: athenzDomain,
            service: athenzService,
            provider: athenzProvider,
            attestationData,
            csr,
        });
    // console.log(`ZTS response: ${JSON.stringify(ztsResponse, null, 4)}`);

    return { privateKey, x509Certificate: ztsResponse.x509Certificate, x509CertificateSigner: ztsResponse.x509CertificateSigner };
}

// Get an identity-document for this GCF from GCP.
function getGcpFunctionAttestationData(ztsUrl) {
    return new Promise((resolve, reject) => {
        const gcpIdentityUrl = `http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience=${ztsUrl}&format=full`;
        // console.log(`Getting GCF identity from: ${gcpIdentityUrl}`);
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
function generateCsr(commonName, csrSubjectFields, altNames) {

    // This is a HORRENDOUS patch to pem.createCSR()
    // As of pem@v1.14.8, pem.createCSR() does not support "URI" SANs (only "DNS" and "IP").
    // However, we need the "spiffe://" alternative-name to be of type "URI".
    // So we override Array.join() - which pem uses internally - to set things right.
    const origArrayJoin = Array.prototype.join;
    Array.prototype.join = function(separator) {
        let result = origArrayJoin.apply(this, arguments);
        if ((separator === '\n') &&
            (this[0] === '[req]') &&
            (this[1] === 'req_extensions = v3_req') &&
            (this[2] === 'distinguished_name = req_distinguished_name')) {
            // Replace "DNS.X = spiffe://" to "URI.X = spiffe://"
            result = result.replace(/\nDNS(\.[0-9]+ = spiffe:\/\/)/g, '\nURI$1')
        }
        return result;
    };

    return new Promise((resolve, reject) =>
        pem.createCSR(
            {
                ...csrSubjectFields,
                commonName,
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
            })).finally(() => Array.prototype.join = origArrayJoin);
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
                    if (response.statusCode !== 201) {
                        // Bad HTTP status code.
                        reject(new Error(`HTTP request to    ${requestUrl}    returned ${response.statusCode} (${response.statusMessage}). Body:\n${responseBody}`));
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
    res.send(await executeAsyncWhileCapturingLogs(async () => {
        console.log("This is NodeJS GCF test");

        // Read configurations.
        const athenzDomain = getMandatoryEnvVar("ATHENZ_DOMAIN");
        const athenzService = getMandatoryEnvVar("ATHENZ_SERVICE");
        const gcpProjectId = getMandatoryEnvVar("GCP_PROJECT_ID");
        const gcpRegion = getMandatoryEnvVar("GCP_REGION");
        const athenzProvider = "sys.gcp." + gcpRegion;
        const ztsUrl = getMandatoryEnvVar("ZTS_URL");
        const certDomain = getMandatoryEnvVar("CERT_DOMAIN");
        const csrCountry= getOptionalEnvVar("CSR_COUNTRY");
        const csrState= getOptionalEnvVar("CSR_STATE");
        const csrLocality= getOptionalEnvVar("CSR_LOCALITY");
        const csrOrganization= getOptionalEnvVar("CSR_ORGANIZATION");
        const csrOrganizationUnit= getOptionalEnvVar("CSR_ORGANIZATION_UNIT");

        const { privateKey, x509Certificate, x509CertificateSigner } = await getSiaCertsDemo(
                athenzDomain,
                athenzService,
                gcpProjectId,
                gcpRegion,
                athenzProvider,
                ztsUrl,
                certDomain,
                csrCountry,
                csrState,
                csrLocality,
                csrOrganization,
                csrOrganizationUnit);

        // Log the SIA certificate.
        // console.log('PRIVATE-KEY:');
        // console.log(privateKey);
        console.log('ATHENZ CERTIFICATE:');
        console.log(x509Certificate);
        console.log('CERTIFICATE SIGNER:');
        console.log(x509Certificate);
    }));
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

function getOptionalEnvVar(envVar) {
    const value = process.env[envVar];
    if (value === undefined) {
        throw new Error(`Mandatory environment-variable \"${envVar}\" is not defined`);
    }
    console.log(`Environment variable:   ${envVar} = \"${value}\"`);
    return value;
}
