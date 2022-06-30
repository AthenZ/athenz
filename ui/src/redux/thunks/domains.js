import { loadingInProcess, loadingSuccess } from '../actions/loading';
import API from '../../api';
import { returnDomainList, loadUserDomainList } from '../actions/domains';

const api = API();

export const getUserDomainsList = () => async (dispatch, getState) => {
    try {
        if (
            !getState().domains.domainsList ||
            getState().domains.domainsList.length === 0
        ) {
            dispatch(loadingInProcess('getUserDomainsList'));
            const domainsList = await api.listUserDomains();
            dispatch(loadUserDomainList(domainsList));
            dispatch(loadingSuccess('getUserDomainsList'));
        } else {
            dispatch(returnDomainList());
        }
    } catch (err) {
        // let response = RequestUtils.errorCheckHelper(err);
        // let reload = response.reload;
        // let error = response.error;
    }
};
