export const selectDomainTemplates = (state) => {
    console.log('selectDomainTemplates', state.templates.domainTemplates);
    return state.templates.domainTemplates
        ? state.templates.domainTemplates
        : [];
};

export const selectServerTemplates = (state) => {
    return state.templates.serverTemplates
        ? state.templates.serverTemplates
        : [];
};
