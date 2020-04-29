/*
 * Copyright 2020 Verizon Media
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
import Header from '../components/header/Header';
import UserDomains from '../components/domain/UserDomains';
import API from '../api';
import styled from '@emotion/styled';
import Head from 'next/head';
// there is an issue with next-link and next-css if the css is not present then it doesnt load so adding this
import 'flatpickr/dist/themes/light.css';
import ManageDomains from '../components/domain/ManageDomains';
import RequestUtils from '../components/utils/RequestUtils';
import Alert from '../components/denali/Alert';
import { MODAL_TIME_OUT } from '../components/constants/constants';
import Error from './_error';

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

export default class ManageDomainsPage extends React.Component {
    static async getInitialProps(props) {
        let api = API(props.req);
        let reload = false;
        let notFound = false;
        let error = undefined;
        const domains = await Promise.all([
            api.listUserDomains(),
            api.getHeaderDetails(),
            api.listAdminDomains(),
            api.getPendingDomainRoleMembersList(),
            api.getForm(),
        ]).catch((err) => {
            let response = RequestUtils.errorCheckHelper(err);
            reload = response.reload;
            error = response.error;
            return [{}, {}, {}, {}, {}];
        });
        return {
            api,
            reload,
            notFound,
            error,
            domains: domains[0],
            headerDetails: domains[1],
            manageDomains: domains[2],
            pending: domains[3],
            _csrf: domains[4],
        };
    }

    constructor(props) {
        super(props);
        this.api = props.api || API();
        this.state = {
            manageDomains: props.manageDomains || [],
            domains: props.domains || [],
            successMessage: '',
        };
        this.loadDomains = this.loadDomains.bind(this);
    }

    loadDomains(successMessage) {
        Promise.all([this.api.listAdminDomains(), this.api.listUserDomains()])
            .then((domains) => {
                this.setState({
                    manageDomains: domains[0],
                    domains: domains[1],
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
        const { reload } = this.props;
        if (reload) {
            window.location.reload();
            return <div />;
        }
        if (this.props.error) {
            return <Error err={this.props.error} />;
        }
        return (
            <div data-testid='page-manage-domains'>
                <Head>
                    <title>Athenz</title>
                </Head>
                <Header
                    showSearch={false}
                    headerDetails={this.props.headerDetails}
                    pending={this.props.pending}
                />
                <MainContentDiv>
                    <AppContainerDiv>
                        <RolesContainerDiv>
                            <RolesContentDiv>
                                <PageHeaderDiv>
                                    <TitleDiv>Manage My Domains</TitleDiv>
                                </PageHeaderDiv>
                                <ManageDomains
                                    domains={this.state.manageDomains}
                                    _csrf={this.props._csrf}
                                    api={this.api}
                                    loadDomains={this.loadDomains}
                                />
                                <Alert
                                    isOpen={this.state.showSuccess}
                                    title={this.state.successMessage}
                                    onClose={() => {
                                        this.setState({ showSuccess: false });
                                    }}
                                    type='success'
                                />
                            </RolesContentDiv>
                        </RolesContainerDiv>
                        <UserDomains
                            domains={this.state.domains}
                            api={this.api}
                        />
                    </AppContainerDiv>
                </MainContentDiv>
            </div>
        );
    }
}
