export const LOAD_HISTORY = 'LOAD_HISTORY';
export const loadHistory = ( domainHistory, domainName, expiry) => ({
    type: LOAD_HISTORY,
    payload: { domainHistory: domainHistory, domainName: domainName, expiry: expiry },
});

export const RETURN_HISTORY = 'RETURN_HISTORY';
export const returnHistory = () => ({
    type: RETURN_HISTORY,
});
