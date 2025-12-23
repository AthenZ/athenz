const appConfig = require('./src/config/config')();

module.exports = {
    publicRuntimeConfig: {
        onCallUrl: appConfig.onCallUrl || appConfig.serverURL,
        organizationDomain: appConfig?.organizationDomain,
    },
};
