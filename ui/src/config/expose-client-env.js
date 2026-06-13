'use strict';

/**
 * Map merged deployment config to NEXT_PUBLIC_* for client-config.js consumption.
 * Used by next.config.js (build) and setup-jest-env.js (tests).
 */
function buildClientEnv(appConfig) {
    if (!appConfig) {
        return {};
    }
    const env = {};
    const onCallUrl = appConfig.onCallUrl || appConfig.serverURL;
    if (onCallUrl) {
        env.NEXT_PUBLIC_ONCALL_URL = onCallUrl;
    }
    if (appConfig.organizationDomain) {
        env.NEXT_PUBLIC_ORGANIZATION_DOMAIN = appConfig.organizationDomain;
    }
    if (appConfig.zms) {
        env.NEXT_PUBLIC_ZMS_URL = appConfig.zms;
    }
    env.NEXT_PUBLIC_RESOURCE_OWNERSHIP_UI = JSON.stringify(
        appConfig.resourceOwnershipUi || {}
    );
    return env;
}

function applyClientEnv(appConfig) {
    Object.assign(process.env, buildClientEnv(appConfig));
}

module.exports = { buildClientEnv, applyClientEnv };
