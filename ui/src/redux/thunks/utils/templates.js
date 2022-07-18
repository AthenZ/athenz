import API from '../../../api';
import { loadingInProcess, loadingSuccess } from '../../actions/loading';
import { loadTemplates } from '../../actions/templates';
import { getExpiryTime } from '../../utils';

const api = API();
const getApi = (domainName = 'home.mshneorson.redux') => {
    const context = { query: { domain: domainName } };
    console.log(
        '!!!!!!!!!!!getApi    context.query.domain',
        context.query.domain
    );
    return API(context);
};

export const getTemplatesApiCall = async (domainName, dispatch) => {
    dispatch(loadingInProcess('getTemplates'));
    const domainTemplateList = await api.getDomainTemplateDetailsList(
        domainName
    );
    const serverTemplateList = [];
    // await api.getServerTemplateDetailsList();
    const expiry = getExpiryTime();
    dispatch(
        loadTemplates(
            domainTemplateList,
            domainName,
            serverTemplateList,
            expiry
        )
    );
    dispatch(loadingSuccess('getTemplates'));
};
