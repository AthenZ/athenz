import {
    DELETE_INBOUND,
    DELETE_OUTBOUND,
    LOAD_MICROSEGMENTATION,
    RETURN_MICROSEGMENTATION,
} from '../actions/microsegmentation';
import produce from 'immer';

export const microsegmentation = (state = {}, action) => {
    const { type, payload } = action;
    switch (type) {
        case LOAD_MICROSEGMENTATION: {
            const { inboundOutboundList, domainName } = payload;
            return {
                domainName: domainName,
                inboundOutboundList: inboundOutboundList,
            };
        }
        case DELETE_INBOUND: {
            const { assertionIdx } = payload;
            const newState = produce(state, (draft) => {
                draft.inboundOutboundList.inbound =
                    draft.inboundOutboundList.inbound.filter(
                        (inbound) => inbound.assertionIdx !== assertionIdx
                    );
            });
            return newState;
        }
        case DELETE_OUTBOUND: {
            const { assertionIdx } = payload;
            const newState = produce(state, (draft) => {
                draft.inboundOutboundList.outbound =
                    draft.inboundOutboundList.outbound.filter(
                        (outbound) => outbound.assertionIdx !== assertionIdx
                    );
            });
            return newState;
        }
        case RETURN_MICROSEGMENTATION:
        default:
            return state;
    }
};
