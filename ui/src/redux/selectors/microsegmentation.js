import AppUtils from '../../components/utils/AppUtils';

export const selectInboundOutboundList = (state) => {
    return state.microsegmentation.inboundOutboundList
        ? AppUtils.deepClone(state.microsegmentation.inboundOutboundList)
        : [];
};
