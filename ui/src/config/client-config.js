// Exposes values from config files that depend on Node.js APIs (not accessible client-side)

function parseJsonEnv(name) {
    const raw = process.env[name];
    if (!raw) {
        return null;
    }
    try {
        return JSON.parse(raw);
    } catch (e) {
        return null;
    }
}

/** Read merged resourceOwnershipUi injected via NEXT_PUBLIC_RESOURCE_OWNERSHIP_UI. */
export function readResourceOwnershipUiFromEnv() {
    return parseJsonEnv('NEXT_PUBLIC_RESOURCE_OWNERSHIP_UI') || {};
}

export const CLIENT_CONFIG = {
    onCallUrl: process.env.NEXT_PUBLIC_ONCALL_URL,
    organizationDomain: process.env.NEXT_PUBLIC_ORGANIZATION_DOMAIN,
    zmsUrl: process.env.NEXT_PUBLIC_ZMS_URL,
};
