export const LOAD_MICROSEGMENTATION = 'LOAD_MICROSEGMENTATION';
export const loadMicrosegmentation = (inboundOutboundList, domainName) => ({
    type: LOAD_MICROSEGMENTATION,
    payload: { inboundOutboundList, domainName },
});

export const RETURN_MICROSEGMENTATION = 'RETURN_MICROSEGMENTATION';
export const returnMicrosegmentation = () => ({
    type: RETURN_MICROSEGMENTATION,
});

export const DELETE_INBOUND = 'DELETE_INBOUND';
export const deleteInboundFromStore = (assertionIdx) => ({
    type: DELETE_INBOUND,
    payload: { assertionIdx },
});

export const DELETE_OUTBOUND = 'DELETE_OUTBOUND';
export const deleteOutboundFromStore = (assertionIdx) => ({
    type: DELETE_OUTBOUND,
    payload: { assertionIdx },
});
