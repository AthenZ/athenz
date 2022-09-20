const fs = require('fs');
const { exec } = require('child_process');
const debug = require('debug')('AthenzUI:server:secrets');
let s3Service = require('./services/s3Service');
const certRefreshTime = 24 * 60 * 60 * 1000; // refresh cert and key once a day
const accessTokenRefreshTime = 60 * 60 * 1000; // refresh cert and key once an hour

function loadFile(key, path) {
    return new Promise((resolve, reject) => {
        fs.readFile(path, (err, body) => {
            if (err) {
                reject(err);
            } else {
                module.exports[key] = body.toString().trim();
                resolve();
            }
        });
    });
}
function fetchSecret(key, keyGroup, secretKey, tlscert, tlskey) {
    return new Promise((resolve, reject) => {
        let command = `ckms-remotecli -env aws -group ${keyGroup} -key ${secretKey} -tlscert ${tlscert} -tlskey ${tlskey}`;
        debug('Executing %s to fetch secret', command);
        exec(command, (error, body, stderr) => {
            if (error || stderr) {
                debug('error in fetchSecret: %o, stdErr: %o', error, stderr);
                reject(error);
            } else {
                module.exports[key] = body.toString().trim();
                resolve();
            }
        });
    });
}
function fetchSecretFromS3(key, s3svc, bucket, s3Key) {
    return new Promise((resolve, reject) => {
        s3svc.getContent(bucket, s3Key, function (err, data) {
            if (err) {
                debug(
                    '[Startup] error in fetchSecretFromS3 for s3K3y=>%s is : %o',
                    s3Key,
                    err
                );
                reject(err);
            } else {
                module.exports[key] = data.toString().trim();
                resolve();
            }
        });
    });
}
module.exports.load = function (config) {
    let promises = [];
    let tlsCert = process.env.HOME + '/ssl/certs/local.cert.pem';
    let tlsKey = process.env.HOME + '/ssl/keys/local.key.pem';
    let msdAuthHeaderPath = process.env.HOME + config.msdAuthHeaderPath;
    if (config.env !== 'local') {
        tlsKey = config.athenzPrivateKeyPath;
        tlsCert = config.athenzX509CertPath;
        msdAuthHeaderPath = config.msdAuthHeaderPath;
    }

    if (config.env === 'athenz.ui' || config.env === 'sys.auth.ui') {
        promises.push(
            fetchSecretFromS3(
                'oktaClient',
                s3Service,
                config.awsSecretsBucketName,
                'okta_client_secret'
            )
        );
        promises.push(
            fetchSecretFromS3(
                'serverCert',
                s3Service,
                config.awsSecretsBucketName,
                'service_x509_cert'
            )
        );
        promises.push(
            fetchSecretFromS3(
                'serverKey',
                s3Service,
                config.awsSecretsBucketName,
                'service_x509_key'
            )
        );
        promises.push(
            fetchSecretFromS3(
                'cookieSession',
                s3Service,
                config.awsSecretsBucketName,
                'session_secret'
            )
        );
    } else {
        promises.push(
            fetchSecret(
                'serverKey',
                config.serverKey.keyGroup,
                config.serverKey.key,
                tlsCert,
                tlsKey
            )
        );
        promises.push(
            fetchSecret(
                'serverCert',
                config.serverCert.keyGroup,
                config.serverCert.key,
                tlsCert,
                tlsKey
            )
        );

        promises.push(
            fetchSecret(
                'oktaClient',
                config.okta.keyGroup,
                config.okta.key,
                tlsCert,
                tlsKey
            )
        );
        promises.push(
            fetchSecret(
                'cookieSession',
                config.cookie.keyGroup,
                config.cookie.key,
                tlsCert,
                tlsKey
            )
        );
    }
    promises.push(loadFile('clientKey', tlsKey));
    promises.push(loadFile('clientCert', tlsCert));
    promises.push(loadFile('msdAuthHeader', msdAuthHeaderPath));

    // Refresh client cert and key once in a day from disk
    setInterval(function () {
        debug('Trying to load latest athenz cert and key from disk..');
        let promises = [];
        promises.push(loadFile('clientKey', tlsKey));
        promises.push(loadFile('clientCert', tlsCert));
        Promise.all(promises)
            .then(() => {
                debug('successfully loaded athenz cert and key from disk');
            })
            .catch((e) => {
                debug(
                    'failed loaded athenz cert and key from disk, err: %s',
                    e
                );
            });
    }, certRefreshTime);

    //Refresh msdAuthHeader every 1 hour
    setInterval(function () {
        debug('Trying to msdAuthHeader from disk..');
        loadFile('msdAuthHeader', config.msdAuthHeaderPath)
            .then(() => {
                debug('successfully loaded msdAuthHeader from disk');
            })
            .catch((e) => {
                debug('failed to load msdAuthHeader from disk, err: %s', e);
            });
    }, accessTokenRefreshTime);

    return Promise.all(promises);
};
