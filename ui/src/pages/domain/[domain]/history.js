/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import React from 'react';
import Header from '../../../components/header/Header';
import UserDomains from '../../../components/domain/UserDomains';
import API from '../../../api';
import styled from '@emotion/styled';
import Head from 'next/head';
import HistoryList from '../../../components/history/HistoryList';
import Tabs from '../../../components/header/Tabs';
import RequestUtils from '../../../components/utils/RequestUtils';
import Error from '../../_error';
import createCache from '@emotion/cache';
import DomainNameHeader from '../../../components/header/DomainNameHeader';
import { getRoles } from '../../../redux/thunks/roles';
import { getDomainData, getDomainHistory } from '../../../redux/thunks/domain';
import { connect } from 'react-redux';
import DomainDetails from '../../../components/header/DomainDetails';
import { selectIsLoading } from '../../../redux/selectors/loading';
import Alert from '../../../components/denali/Alert';
import { CacheProvider } from '@emotion/react';
import { ReduxPageLoader } from '../../../components/denali/ReduxPageLoader';

const AppContainerDiv = styled.div`
    align-items: stretch;
    flex-flow: row nowrap;
    height: 100%;
    display: flex;
    justify-content: flex-start;
`;

const MainContentDiv = styled.div`
    flex: 1 1 calc(100vh - 60px);
    overflow: hidden;
    font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
`;

const HistoryContainerDiv = styled.div`
    align-items: stretch;
    flex: 1 1;
    height: calc(100vh - 60px);
    display: flex;
    flex-direction: column;
    overflow: auto;
`;

const HistoryContentDiv = styled.div``;

const PageHeaderDiv = styled.div`
    background: linear-gradient(to top, #f2f2f2, #fff);
    padding: 20px 30px 0;
`;

const TitleDiv = styled.div`
    font: 600 20px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    margin-bottom: 10px;
`;

export async function getServerSideProps(context) {
    let api = API(context.req);
    let reload = false;
    let notFound = false;
    let error = null;
    const historyData = await Promise.all([api.getForm()]).catch((err) => {
        let response = RequestUtils.errorCheckHelper(err);
        reload = response.reload;
        error = response.error;
        return [{}];
    });
    return {
        props: {
            reload,
            notFound,
            error,
            domain: context.query.domain,
            _csrf: historyData[0],
            nonce: context.req.headers.rid,
        },
    };
}
class HistoryPage extends React.Component {
    constructor(props) {
        super(props);
        this.api = API();
        this.cache = createCache({
            key: 'athenz',
            nonce: this.props.nonce,
        });
        this.state = {
            errorMessage: '',
            showError: false,
        };
        this.showError = this.showError.bind(this);
    }

    componentDidMount() {
        const { getRoles, domain, getDomainData, userName, getHistory } =
            this.props;
        Promise.all([
            getHistory(domain, this.props._csrf),
            getRoles(domain),
            getDomainData(domain, userName),
        ]).catch((err) => {
            this.showError(RequestUtils.fetcherErrorCheckHelper(err));
        });
    }

    showError(errorMessage) {
        this.setState({
            showError: true,
            errorMessage: errorMessage,
        });
    }

    render() {
        const { domain, isLoading, reload, _csrf } = this.props;
        if (reload) {
            window.location.reload();
            return <div />;
        }
        if (this.props.error) {
            return <Error err={this.props.error} />;
        }

        if (this.state.showError) {
            return (
                <Alert
                    isOpen={this.state.showError}
                    title={this.state.errorMessage}
                    onClose={() => {}}
                    type='danger'
                />
            );
        }

        return isLoading.includes('getDomainData') ? (
            <ReduxPageLoader message={'Loading domain data'} />
        ) : (
            <CacheProvider value={this.cache}>
                <div data-testid='history'>
                    <Head>
                        <title>Athenz</title>
                    </Head>
                    <Header showSearch={true} />
                    <MainContentDiv>
                        <AppContainerDiv>
                            <HistoryContainerDiv>
                                <HistoryContentDiv>
                                    <PageHeaderDiv>
                                        <DomainNameHeader domainName={domain} />
                                        <DomainDetails
                                            api={this.api}
                                            _csrf={_csrf}
                                        />
                                        <Tabs
                                            domain={domain}
                                            selectedName={'history'}
                                        />
                                    </PageHeaderDiv>
                                    <HistoryList
                                        domain={domain}
                                        _csrf={_csrf}
                                    />
                                </HistoryContentDiv>
                            </HistoryContainerDiv>
                            <UserDomains domain={domain} />
                        </AppContainerDiv>
                    </MainContentDiv>
                </div>
            </CacheProvider>
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        isLoading: selectIsLoading(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    getHistory: (domainName, _csrf) =>
        dispatch(getDomainHistory(domainName, null, null, _csrf)),
    getRoles: (domainName) => dispatch(getRoles(domainName)),
    getDomainData: (domainName, userName) =>
        dispatch(getDomainData(domainName, userName)),
});

export default connect(mapStateToProps, mapDispatchToProps)(HistoryPage);
