// Exposes values from config files that depend on Node.js APIs (not accessible client-side)
export const CLIENT_CONFIG = {
    onCallUrl: process.env.NEXT_PUBLIC_ONCALL_URL,
    organizationDomain: process.env.NEXT_PUBLIC_ORGANIZATION_DOMAIN,
};
