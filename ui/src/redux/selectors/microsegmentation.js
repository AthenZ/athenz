export const selectInboundOutboundList = (state) => {
    return state.microsegmentation.inboundOutboundList
        ? JSON.parse(
              JSON.stringify(state.microsegmentation.inboundOutboundList)
          )
        : [];
};

export const selectInboundList = (state) => {
    return state.microsegmentation.inboundOutboundList?.inbound
        ? state.microsegmentation.inboundOutboundList.inbound
        : [];
};

export const selectOutboundList = (state) => {
    return state.microsegmentation.inboundOutboundList?.outbound
        ? state.microsegmentation.inboundOutboundList.outbound
        : [];
};
