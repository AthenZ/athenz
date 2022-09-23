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
import Header from '../../components/header/Header';
import UserDomains from '../../components/domain/UserDomains';
import API from '../../api';
import styled from '@emotion/styled';
import Head from 'next/head';

import RequestUtils from '../../components/utils/RequestUtils';
import { MODAL_TIME_OUT } from '../../components/constants/constants';
import Error from '../_error';
import createCache from '@emotion/cache';
import ManageDomains from '../../components/domain/ManageDomains';
import { selectIsLoading } from '../../redux/selectors/loading';
import { connect } from 'react-redux';
import { getBusinessServicesAll } from '../../redux/thunks/domains';
import { CacheProvider } from '@emotion/react';
import Alert from '../../components/denali/Alert';
import { ReduxPageLoader } from '../../components/denali/ReduxPageLoader';

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

const RolesContainerDiv = styled.div`
    align-items: stretch;
    flex: 1 1;
    height: calc(100vh - 60px);
    overflow: auto;
    display: flex;
    flex-direction: column;
`;

const RolesContentDiv = styled.div``;

const PageHeaderDiv = styled.div`
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
    var bServicesParams = {
        category: 'domain',
        attributeName: 'businessService',
        userName: context.req.session.shortId,
    };
    const domains = await Promise.all([
        api.getHeaderDetails(),
        api.listAdminDomains(),
        api.getPendingDomainMembersList(),
        api.getForm(),
        api.getMeta(bServicesParams),
    ]).catch((err) => {
        let response = RequestUtils.errorCheckHelper(err);
        reload = response.reload;
        error = response.error;
        return [{}, {}, {}, {}, {}];
    });

    let businessServiceOptions = [];
    if (domains[4] && domains[4].validValues) {
        domains[4].validValues.forEach((businessService) => {
            let bServiceOnlyId = businessService.substring(
                0,
                businessService.indexOf(':')
            );
            let bServiceOnlyName = businessService.substring(
                businessService.indexOf(':') + 1
            );
            businessServiceOptions.push({
                value: bServiceOnlyId,
                name: bServiceOnlyName,
            });
        });
    }

    return {
        props: {
            reload,
            notFound,
            error,
            headerDetails: domains[0],
            manageDomains: domains[1],
            pending: domains[2],
            _csrf: domains[3],
            nonce: context.req.headers.rid,
            validBusinessServices: businessServiceOptions,
        },
    };
}

class ManageDomainsPage extends React.Component {
    constructor(props) {
        super(props);
        this.api = API();
        this.state = {
            manageDomains: props.manageDomains || [],
            successMessage: '',
            errorMessage: '',
            showError: false,
        };
        this.showError = this.showError.bind(this);
        this.loadDomains = this.loadDomains.bind(this);
        this.cache = createCache({
            key: 'athenz',
            nonce: this.props.nonce,
        });
    }

    componentDidMount() {
        const { getBusinessServicesAll } = this.props;
        Promise.all([getBusinessServicesAll()]).catch((err) => {
            this.showError(RequestUtils.fetcherErrorCheckHelper(err));
        });
    }

    showError(errorMessage) {
        this.setState({
            showError: true,
            errorMessage: errorMessage,
        });
    }

    loadDomains(successMessage) {
        Promise.all([this.api.listAdminDomains()])
            .then((domains) => {
                this.setState({
                    manageDomains: domains[0],
                    showSuccess: true,
                    successMessage,
                });
                setTimeout(
                    () =>
                        this.setState({
                            showSuccess: false,
                        }),
                    MODAL_TIME_OUT
                );
            })
            .catch((err) => {
                let message = '';
                if (err.statusCode === 0) {
                    message = 'Okta expired. Please refresh the page';
                } else {
                    message = `Status: ${err.statusCode}. Message: ${err.body.message}`;
                }
                this.setState({
                    errorMessage: message,
                });
            });
    }

    render() {
        const { reload, isLoading } = this.props;
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

        return isLoading.length !== 0 ? (
            <ReduxPageLoader message={'Loading domain data'} />
        ) : (
            <CacheProvider value={this.cache}>
                <div data-testid='page-manage-domains'>
                    <Head>
                        <title>Athenz</title>
                    </Head>
                    <Header showSearch={false} />
                    <MainContentDiv>
                        <AppContainerDiv>
                            <RolesContainerDiv>
                                <RolesContentDiv>
                                    <PageHeaderDiv>
                                        <TitleDiv>Manage My Domains</TitleDiv>
                                    </PageHeaderDiv>
                                    <ManageDomains
                                        successMessage={
                                            this.state.successMessage
                                        }
                                        domains={this.state.manageDomains}
                                        _csrf={this.props._csrf}
                                        api={this.api}
                                        loadDomains={this.loadDomains}
                                        userId={this.props.headerDetails.userId}
                                        validBusinessServices={
                                            this.props.validBusinessServices
                                        }
                                    />
                                </RolesContentDiv>
                            </RolesContainerDiv>
                            <UserDomains api={this.api} />
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
    getBusinessServicesAll: () => dispatch(getBusinessServicesAll()),
});

export default connect(mapStateToProps, mapDispatchToProps)(ManageDomainsPage);
