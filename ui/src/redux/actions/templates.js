export const LOAD_TEMPLATES = 'LOAD_TEMPLATES';
export const loadTemplates = (
    domainTemplates,
    serverTemplates,
    domainName,
    expiry
) => ({
    type: LOAD_TEMPLATES,
    payload: {
        domainTemplates: domainTemplates,
        serverTemplate: serverTemplates,
        domainName: domainName,
        expiry: expiry,
    },
});

export const RETURN_TEMPLATES = 'RETURN_TEMPLATES';
export const returnTemplates = () => ({
    type: RETURN_TEMPLATES,
});
