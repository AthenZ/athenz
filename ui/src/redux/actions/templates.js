// TODO roy - check if need to add to the store instead of current implementation odf using roles and servce expiry
export const LOAD_TEMPLATES = 'LOAD_TEMPLATES';
export const loadTemplates = (
    domainTemplates,
    domainName,
    serverTemplates,
    expiry
) => ({
    type: LOAD_TEMPLATES,
    payload: {
        domainTemplates: domainTemplates,
        domainName: domainName,
        expiry: expiry,
    },
});

export const RETURN_TEMPLATES = 'RETURN_TEMPLATES';
export const returnTemplates = () => ({
    type: RETURN_TEMPLATES,
});
