const api = require('./api');
const AuthStrategy = require('./AuthStrategy');
const awsSSO = require('../aws-sso/aws');

module.exports.route = function (expressApp, config, secrets) {
    // client and api routes
    api.route(expressApp);

    // AWS SSO Routes
    expressApp.get('/aws/sso/metadata', awsSSO.getMetadata);
    expressApp.get('/aws/sso/dev/:accountNumber/:roleName', awsSSO.awsLogin);
    expressApp.get('/aws/sso/dev/:accountNumber', awsSSO.awsLogin);
    expressApp.get('/aws/sso/dev', awsSSO.awsLogin);

    // We want the admin endpoint asking for PWDs frequently
    const okta = AuthStrategy.okta(config, secrets, 120);
    expressApp.get('/aws/sso/admin', okta.protect(), awsSSO.awsLogin);
    expressApp.get('/aws/sso/admin/:accountNumber/:roleName', awsSSO.awsLogin);
    expressApp.get('/aws/sso/admin/:accountNumber', awsSSO.awsLogin);
};
