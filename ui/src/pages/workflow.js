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
import API from '../api.js';
import styled from '@emotion/styled';
import Head from 'next/head';
import PendingApprovalTable from '../components/pending-approval/PendingApprovalTable';
// there is an issue with next-link and next-css if the css is not present then it doesnt load so adding this
import 'flatpickr/dist/themes/light.css';
import RequestUtils from '../components/utils/RequestUtils';
import Error from './_error';

const HomeContainerDiv = styled.div`
    flex: 1 1;
`;

const WorkFlowSectionDiv = styled.div`
    padding: 0 30px 20px;
`;

const TitleDiv = styled.div`
    font: 600 20px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
`;

const PageHeaderDiv = styled.div`
    padding: 20px 30px;
`;

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

const WorkFlowDiv = styled.div`
    align-items: stretch;
    flex: 1 1;
    height: calc(100vh - 60px);
    overflow: auto;
`;

export default class Workflow extends React.Component {
    static async getInitialProps({ req }) {
        let api = API(req);
        let reload = false;
        let error = null;
        const domains = await Promise.all([
            api.listUserDomains(),
            api.getHeaderDetails(),
            api.getForm(),
            api.getPendingDomainRoleMembersList(),
        ]).catch((err) => {
            let response = RequestUtils.errorCheckHelper(err);
            reload = response.reload;
            error = response.error;
            return [{}, {}, {}, {}];
        });
        return {
            api,
            reload,
            error,
            domains: domains[0],
            headerDetails: domains[1],
            pendingData: domains[3],
            _csrf: domains[2],
        };
    }

    constructor(props) {
        super(props);
        this.api = props.api || API();
        this.state = {
            selected: this.props.option || 'domain',
            searchText: '',
        };
    }

    render() {
        if (this.props.reload) {
            window.location.reload();
            return <div />;
        }
        if (this.props.error) {
            return <Error err={this.props.error} />;
        }
        return (
            <div data-testid='pending-approval'>
                <Head>
                    <title>Athenz</title>
                </Head>
                <Header
                    showSearch={true}
                    headerDetails={this.props.headerDetails}
                    pending={this.props.pendingData}
                />
                <MainContentDiv>
                    <AppContainerDiv>
                        <HomeContainerDiv>
                            <WorkFlowDiv>
                                <div>
                                    <PageHeaderDiv>
                                        <TitleDiv>
                                            Pending Items for Approval
                                        </TitleDiv>
                                    </PageHeaderDiv>
                                    <WorkFlowSectionDiv>
                                        <PendingApprovalTable
                                            api={this.api}
                                            principal={
                                                'user.' +
                                                this.props.headerDetails.userId
                                            }
                                            domains={this.props.domains}
                                            pendingData={this.props.pendingData}
                                            _csrf={this.props._csrf}
                                        />
                                    </WorkFlowSectionDiv>
                                </div>
                            </WorkFlowDiv>
                        </HomeContainerDiv>
                        <UserDomains
                            domains={this.props.domains}
                            api={this.api}
                            hideDomains={true}
                        />
                    </AppContainerDiv>
                </MainContentDiv>
            </div>
        );
    }
}
