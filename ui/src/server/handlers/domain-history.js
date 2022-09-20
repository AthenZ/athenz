const debug = require('debug')('AthenzUI:server:handlers:domain-history');

module.exports = function (
    req,
    resource,
    params,
    config,
    callback,
    userService,
    errorHandler
) {
    let endDate = new Date().getTime();
    //TODO move range to config
    const range = 3;
    let startDate = new Date().getTime() - range * 31 * 24 * 60 * 60 * 1000;

    if (
        !isNaN(Date.parse(params.startDate)) &&
        !isNaN(Date.parse(params.endDate))
    ) {
        startDate = new Date(params.startDate).getTime();
        endDate = new Date(params.endDate).getTime();
    }
    let role = params.roleName;
    let dynamoParams = {
        TableName: 'Athenz-Auditlog',
        IndexName: 'auditDomain-auditWhenEpoch-index',
        KeyConditionExpression:
            '#auditDomain = :auditDomain and #auditWhenEpoch between :startDate and :endDate',
        ExpressionAttributeNames: {
            '#auditDomain': 'auditDomain',
            '#auditWhenEpoch': 'auditWhenEpoch',
        },
        ExpressionAttributeValues: {
            ':auditDomain': params.domainName,
            ':startDate': startDate,
            ':endDate': endDate,
        },
        ScanIndexForward: false,
    };

    if (role !== 'null' && role !== 'ALL') {
        dynamoParams.ExpressionAttributeValues[':role'] = role;
        dynamoParams.FilterExpression = 'auditEntity=:role';
    }

    let history = [];

    req.clients.db.query(dynamoParams, function (err, json) {
        if (err) {
            debug(
                `principal: ${req.session.shortId} rid: ${
                    req.headers.rid
                } Error from ZMS while calling domainHistory API: ${JSON.stringify(
                    err
                )}`
            );
            return callback(errorHandler.fetcherError(err));
        }
        json.Items.forEach(function (audit) {
            history.push({
                action: audit.auditApi,
                who: audit.auditFullName,
                whoFull: userService.getUserFullName(audit.auditFullName),
                whatEntity: audit.auditEntity,
                when: audit.auditWhen,
                details: audit.auditDetails,
                epoch: audit.auditWhenEpoch,
                why: audit.auditWhy,
            });
        });
        history.sort(function (a, b) {
            return b.epoch - a.epoch;
        });
        return callback(null, history);
    });
};
