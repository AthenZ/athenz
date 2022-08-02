export const LOAD_SERVICE_DEPENDENCIES = 'LOAD_SERVICE_DEPENDENCIES';
export const loadServiceDependencies = (
    serviceDependencies,
    domainName,
    expiry
) => ({
    type: LOAD_SERVICE_DEPENDENCIES,
    payload: {
        serviceDependencies: serviceDependencies,
        domainName: domainName,
        expiry: expiry,
    },
});

export const RETURN_SERVICE_DEPENDENCIES = 'RETURN_SERVICE_DEPENDENCIES';
export const returnServiceDependencies = () => ({
    type: RETURN_SERVICE_DEPENDENCIES,
});
