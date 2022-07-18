import API from '../../api';
import { loadingSuccess } from '../actions/loading';
import {
    deleteTemplateFromStore,
    loadTemplates,
    returnTemplates,
} from '../actions/templates';
import { storeTemplates } from '../actions/domains';
import { getTemplatesApiCall } from './utils/templates';
import { isExpired } from '../utils';

const api = API();

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
            dispatch(storeTemplates(getState().templates));
            if (
                getState().domains[domainName] &&
                getState().domains[domainName].templates &&
                !isExpired(getState().domains[domainName].templates.expiry)
            ) {
                dispatch(
                    loadTemplates(
                        getState().domains[domainName].templates.templates,
                        domainName,
                        getState().domains[domainName].templates.expiry
                    )
                );
            } else {
                await getTemplatesApiCall(domainName, dispatch);
            }
        } else if (isExpired(getState().templates.expiry)) {
            if (getState().templates.domainName !== domainName) {
                dispatch(storeTemplates(getState().templates));
            }
            await getTemplatesApiCall(domainName, dispatch);
        } else {
            dispatch(returnTemplates());
        }
    } else {
        try {
            await getTemplatesApiCall(domainName, dispatch);
        } catch (err) {
            console.log('in catch with ', err);
            dispatch(loadingSuccess('getTemplates'));
        }
    }
};

export const updateTemplate =
    (params, csrf, onSuccess, onFail) => async (dispatch, getState) => {
        this.api
            .updateTemplate(params, csrf)
            .then(() => {
                onSuccess();
            })
            .catch((err) => {
                onFail(err);
            });
    };
