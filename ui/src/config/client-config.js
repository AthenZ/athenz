import getConfig from 'next/config';
const { publicRuntimeConfig } = getConfig() || {};

// Exposes values from config files that depend on Node.js APIs (not accessible client-side)
export const CLIENT_CONFIG = {
    onCallUrl: publicRuntimeConfig?.onCallUrl,
};
