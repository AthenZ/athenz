const rdlRest = require('../rdl-rest');
const CLIENTS = {};
const AWS = require('aws-sdk');
const debug = require('debug')('AthenzUI:server:clients');
const userService = require('../server/services/userService');
const secretUtils = require('./utils/secretsUtils');

let requestOpts = {
    strictSSL: true,
};

const certRefreshTime = 60 * 60 * 1000; // refresh cert and key every hour
const awsCredsRefreshTime = 6 * 60 * 60 * 1000; // refresh aws temporary creds every 6 hours
const userDataRefreshTime = 5 * 60 * 1000; // refresh user data every 5 mins

let athenzHeader = {};

const athenzHeaderKey = 'Athenz-Authorization';

function refreshCertClients(config, secrets) {
    debug('refreshing ZMS/ZTS/MSD clients');
    requestOpts.key = secrets.clientKey;
    requestOpts.cert = secrets.clientCert;

    athenzHeader = {
        key: athenzHeaderKey,
        val: secretUtils.authHeader(secrets.msdAuthHeader),
    };

    CLIENTS.zms = rdlRest({
        apiHost: config.zms,
        rdl: require('../config/zms.json'),
        requestOpts: requestOpts,
    });
    CLIENTS.zts = rdlRest({
        apiHost: config.zts,
        rdl: require('../config/zts.json'),
        requestOpts: requestOpts,
    });
    CLIENTS.msd = rdlRest({
        apiHost: config.msd,
        rdl: require('../config/msd.json'),
        requestOpts: requestOpts,
    });
    return Promise.resolve();
}

function initializeAuditLogClient(config, durationSeconds) {
    return new Promise((resolve, reject) => {
        let params = {
            domainName: config.awsDBDomain,
            role: config.awsDBRole,
            durationSeconds,
        };
        if (config.env === 'athenz.ui' || config.env === 'sys.auth.ui') {
            CLIENTS.db = new AWS.DynamoDB.DocumentClient();
            return resolve();
        }
        return CLIENTS.zts().getAWSTemporaryCredentials(
            params,
            function (err, json) {
                if (err) {
                    debug(
                        'Failed to refresh AWS Credentials for Audit logs from DynamoDB: %o',
                        err
                    );
                    reject(err);
                } else {
                    debug('Refreshing AWS Credentials for Audit Logs');
                    let creds = new AWS.Credentials(
                        json.accessKeyId,
                        json.secretAccessKey,
                        json.sessionToken
                    );
                    CLIENTS.db = new AWS.DynamoDB.DocumentClient({
                        credentials: creds,
                    });
                    resolve();
                }
            }
        );
    });
}

function initializeS3Client(config, durationSeconds) {
    return new Promise((resolve, reject) => {
        const params = {
            domainName: config.awsYanisDomain,
            role: config.awsYanisRole,
            durationSeconds,
        };
        if (config.env === 'athenz.ui' || config.env === 'sys.auth.ui') {
            return userService.refreshUserData(config);
        }
        return CLIENTS.zts().getAWSTemporaryCredentials(
            params,
            function (err, json) {
                if (err) {
                    debug(
                        'Failed to refresh AWS Credentials for Yanis data from S3: %o',
                        err
                    );
                    reject(err);
                } else {
                    debug('Refreshing AWS Credentials for Yanis data');
                    const creds = new AWS.Credentials(
                        json.accessKeyId,
                        json.secretAccessKey,
                        json.sessionToken
                    );
                    CLIENTS.yanis = new AWS.S3({ credentials: creds });
                    debug('initialized yanis client, getting data from S3 now');
                    return userService.refreshUserData(config, CLIENTS.yanis);
                }
            }
        );
    });
}

function refreshAWSClients(config) {
    debug('refreshing AWS clients');
    const durationSeconds = 12 * 60 * 60;
    let promises = [];
    AWS.config.update({
        region: 'us-west-2',
    });
    promises.push(initializeAuditLogClient(config, durationSeconds));
    promises.push(initializeS3Client(config, durationSeconds));
    return Promise.all(promises);
}

function setOktaCookieinClients() {
    return {
        cookie: function (currentReq) {
            let cookie = '';
            /*jshint sub: true */
            if (currentReq.okta && currentReq.cookies['okta_at']) {
                cookie += 'okta_at=' + currentReq.cookies['okta_at'] + ';';
            }

            if (currentReq.okta && currentReq.cookies['okta_it']) {
                cookie += 'okta_it=' + currentReq.cookies['okta_it'] + ';';
            }
            return cookie;
        },
    };
}

function setHeaderinClients(req) {
    return {
        cookie: setOktaCookieinClients(req).cookie,
        [athenzHeader.key]: function () {
            return athenzHeader.val;
        },
    };
}

module.exports.load = function load(config, secrets) {
    setInterval(function () {
        refreshCertClients(config, secrets)
            .then(() => debug('ZMS/ZTS/MSD clients refreshed successfully'))
            .catch((e) =>
                debug('ZMS/ZTS/MSD clients failed to refresh, err: %o', e)
            );
    }, certRefreshTime);

    setInterval(function () {
        refreshAWSClients(config)
            .then(() => debug('AWS clients refreshed successfully'))
            .catch((e) => debug('AWS clients failed to refresh, err: %o', e));
    }, awsCredsRefreshTime);

    setInterval(function () {
        userService
            .refreshUserData(config, CLIENTS.yanis)
            .then(() => debug('User data refreshed successfully'))
            .catch((e) => debug('User data failed to refresh, err: %o', e));
    }, userDataRefreshTime);

    // need to load CLIENTS.zts before creating the AWS clients
    return refreshCertClients(config, secrets).then(refreshAWSClients(config));
};

module.exports.middleware = function middleware() {
    return (req, res, next) => {
        req.clients = {
            zms: CLIENTS.zms(req, setOktaCookieinClients(req)),
            zts: CLIENTS.zts(req, setOktaCookieinClients(req)),
            msd: CLIENTS.msd(req, setHeaderinClients(req)),
            db: CLIENTS.db,
            yanis: CLIENTS.yanis,
        };
        next();
    };
};
