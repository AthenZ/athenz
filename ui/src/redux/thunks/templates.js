import API from '../../api';
import { loadingInProcess, loadingSuccess } from '../actions/loading';
import {
    addTemplateToStore,
    deleteTemplateFromStore,
    loadTemplates,
    returnTemplates,
} from '../actions/templates';
import { storeTemplates } from '../actions/domains';
import { getExpiryTime } from '../utils';

const api = API();

export const addTemplate =
    (templateName, template, _csrf, onSuccess, onFail) =>
    async (dispatch, getState) => {
        let templateList = [];
        let domainName = getState().templates.domainName;
        // problem if going to else maybe was added between refreshes
        if (getState().templates.expiry <= 0) {
            templateList = await api.getTemplates(templateName);
            dispatch(loadTemplates(templateList, domainName, 5));
        } else {
            templateList = getState().templates.templates;
        }
        if (templateList.includes(templateName)) {
            // return error message
        }
        api.addTemplate(
            domainName,
            templateName,
            template.description,
            template.providerEndpoint,
            template.keyId,
            template.keyValue,
            _csrf
        )
            .then(() => {
                dispatch(
                    addTemplateToStore(domainName, templateName, template)
                );
                onSuccess(`${domainName}-${templateName}`, false);
            })
            .catch((err) => {
                onFail(err);
            });
    };

export const deleteTemplate =
    (templateName, _csrf, onSuccess, onFail) => async (dispatch, getState) => {
        let domainName = getState().templates.domainName;
        await api
            .deleteTemplate(domainName, templateName, _csrf)
            .then(() => {
                dispatch(deleteTemplateFromStore(templateName, domainName));
                onSuccess();
            })
            .catch((err) => {
                onFail(err);
            });
    };

export const getTemplates = (domainName) => async (dispatch, getState) => {
    if (getState().templates.expiry) {
        if (getState().templates.domainName !== domainName) {
            dispatch(loadingInProcess('getTemplates'));
            dispatch(storeTemplates(getState().templates));
            if (
                getState().domains[domainName] &&
                getState().domains[domainName].templates &&
                getState().domains[domainName].templates.expiry > 0
            ) {
                dispatch(
                    loadTemplates(
                        getState().domains[domainName].templates,
                        domainName,
                        getState().domains[domainName].templates.expiry
                    )
                );
            } else {
                const domainTemplateList =
                    await api.getDomainTemplateDetailsList(domainName);
                const serverTemplateList =
                    await api.getServerTemplateDetailsList();
                const expiry = getExpiryTime();
                dispatch(
                    loadTemplates(
                        domainTemplateList,
                        serverTemplateList,
                        domainName,
                        expiry
                    )
                );
                dispatch(loadingSuccess('getTemplates'));
            }
        } else if (getState().templates.expiry <= 0) {
            if (getState().templates.domainName !== domainName) {
                dispatch(storeTemplates(getState().templates));
            }
            dispatch(loadingInProcess('getTemplates'));
            const domainTemplateList = await api.getDomainTemplateDetailsList(
                domainName
            );
            const serverTemplateList = await api.getServerTemplateDetailsList();
            const expiry = getExpiryTime();
            dispatch(
                loadTemplates(
                    domainTemplateList,
                    serverTemplateList,
                    domainName,
                    expiry
                )
            );
            dispatch(loadingSuccess('getTemplates'));
        } else {
            dispatch(returnTemplates());
        }
    } else {
        dispatch(loadingInProcess('getTemplates'));
        try {
            const domainTemplateList = await api.getDomainTemplateDetailsList(
                domainName
            );
            //need to understand why can't make the api call
            const serverTemplateList = await api.getServerTemplateDetailsList();
            // const serverTemplateList = [];
            console.log(
                'the domain templates',
                domainTemplateList,
                'the server templates',
                serverTemplateList
            );
            const expiry = getExpiryTime();
            dispatch(
                loadTemplates(
                    domainTemplateList,
                    serverTemplateList,
                    domainName,
                    expiry
                )
            );
            dispatch(loadingSuccess('getTemplates'));
        } catch (err) {
            console.log('in catch with ', err);
            dispatch(loadingSuccess('getTemplates'));
        }
    }
};
