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

import RequestUtils from '../../../components/utils/RequestUtils';
import Tabs from '../../../components/header/Tabs';
import Error from '../../_error';
import DomainNameHeader from '../../../components/header/DomainNameHeader';
import { getDomainData } from '../../../redux/thunks/domain';
import { connect } from 'react-redux';
import { getPolicies } from '../../../redux/thunks/policies';
import PolicyList from '../../../components/policy/PolicyList';
import { getRoles } from '../../../redux/thunks/roles';
import { selectIsLoading } from '../../../redux/selectors/loading';
import DomainDetails from '../../../components/header/DomainDetails';
import Alert from '../../../components/denali/Alert';
import createCache from '@emotion/cache';
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

const PoliciesContainerDiv = styled.div`
    align-items: stretch;
    flex: 1 1;
    height: calc(100vh - 60px);
    overflow: auto;
    display: flex;
    flex-direction: column;
`;

const PoliciesContentDiv = styled.div``;

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
    const domains = await Promise.all([api.getForm()]).catch((err) => {
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
            userName: context.req.session.shortId,
            domainName: context.query.domain,
            _csrf: domains[0],
            nonce: context.req.headers.rid,
        },
    };
}

class PolicyPage extends React.Component {
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
        const { getPolicies, domainName, getDomainData, userName, getRoles } =
            this.props;
        Promise.all([
            getDomainData(domainName, userName),
            getPolicies(domainName),
            getRoles(domainName),
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
        const { domainName, reload, isLoading, _csrf } = this.props;
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
                <div data-testid='policy'>
                    <Head>
                        <title>Athenz</title>
                    </Head>
                    <Header showSearch={true} />
                    <MainContentDiv>
                        <AppContainerDiv>
                            <PoliciesContainerDiv>
                                <PoliciesContentDiv>
                                    <PageHeaderDiv>
                                        <DomainNameHeader
                                            domainName={domainName}
                                        />
                                        <DomainDetails
                                            api={this.api}
                                            _csrf={_csrf}
                                        />
                                        <Tabs
                                            domain={domainName}
                                            selectedName={'policies'}
                                        />
                                    </PageHeaderDiv>
                                    <PolicyList
                                        domain={domainName}
                                        _csrf={_csrf}
                                    />
                                </PoliciesContentDiv>
                            </PoliciesContainerDiv>
                            <UserDomains domain={domainName} />
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
    getPolicies: (domainName) => dispatch(getPolicies(domainName)),
    getDomainData: (domainName, userName) =>
        dispatch(getDomainData(domainName, userName)),
    getRoles: (domainName) => dispatch(getRoles(domainName)),
});

export default connect(mapStateToProps, mapDispatchToProps)(PolicyPage);
