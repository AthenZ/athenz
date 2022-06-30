export const LOAD_ASSERTIONS = 'LOAD_ASSERTIONS';
export const loadAssertions = (assertions, policyFullName, version, expiry) => ({
    type: LOAD_ASSERTIONS,
    payload: { assertions: assertions, policyFullName: policyFullName, version: version, expiry: expiry },
});

export const RETURN_ASSERTIONS = 'RETURN_ASSERTIONS';
export const returnAssertions = () => ({
    type: RETURN_ASSERTIONS,
});
