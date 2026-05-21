const appConfig = require('./src/config/config')();

module.exports = {
    env: {
        NEXT_PUBLIC_ONCALL_URL: appConfig?.onCallUrl || appConfig.serverURL,
        NEXT_PUBLIC_ORGANIZATION_DOMAIN: appConfig?.organizationDomain,
    },
};
