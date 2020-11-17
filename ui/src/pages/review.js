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
import RoleDetails from '../components/header/RoleDetails';
import ReviewList from '../components/review/ReviewList';
import RequestUtils from '../components/utils/RequestUtils';
import RoleTabs from '../components/header/RoleTabs';
import RoleNameHeader from '../components/header/RoleNameHeader';
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
    background: linear-gradient(to top, #f2f2f2, #fff);
    padding: 20px 30px 0;
`;

export default class ReviewPage extends React.Component {
    static async getInitialProps(props) {
        let api = API(props.req);
        let reload = false;
        let notFound = false;
        let error = undefined;
        const roles = await Promise.all([
            api.listUserDomains(),
            api.getHeaderDetails(),
            api.getDomain(props.query.domain),
            api.getRole(
                props.query.domain,
                props.query.role,
                false,
                false,
                false
            ),
            api.getRole(
                props.query.domain,
                props.query.role,
                false,
                true,
                false
            ),
            api.getPendingDomainRoleMembersList(),
            api.getForm(),
        ]).catch((err) => {
            let response = RequestUtils.errorCheckHelper(err);
            reload = response.reload;
            error = response.error;
            return [{}, {}, {}, {}, {}, {}, {}];
        });
        return {
            api,
            reload,
            notFound,
            error,
            domains: roles[0],
            domain: props.query.domain,
            role: props.query.role,
            members: roles[3].roleMembers,
            expandMembers: roles[4].roleMembers,
            headerDetails: roles[1],
            domainDeails: roles[2],
            auditEnabled: roles[2].auditEnabled,
            roleDetails: roles[3],
            pending: roles[5],
            _csrf: roles[6],
        };
    }

    constructor(props) {
        super(props);
        this.api = props.api || API();
    }

    render() {
        const {
            domain,
            reload,
            roleDetails,
            role,
            members,
            expandMembers,
            isDomainAuditEnabled,
            _csrf,
        } = this.props;
        if (reload) {
            window.location.reload();
            return <div />;
        }
        if (this.props.error) {
            return <Error err={this.props.error} />;
        }

        let roleMembers = roleDetails.trust ? expandMembers : members;

        return (
            <div data-testid='member'>
                <Head>
                    <title>Athenz</title>
                </Head>
                <Header
                    showSearch={true}
                    headerDetails={this.props.headerDetails}
                    pending={this.props.pending}
                />
                <MainContentDiv>
                    <AppContainerDiv>
                        <RolesContainerDiv>
                            <RolesContentDiv>
                                <PageHeaderDiv>
                                    <RoleNameHeader
                                        domain={domain}
                                        role={role}
                                        roleDetails={roleDetails}
                                    />
                                    <RoleDetails
                                        roleDetails={roleDetails}
                                        api={this.api}
                                        _csrf={_csrf}
                                        productMasterLink={
                                            this.props.headerDetails
                                                .productMasterLink
                                        }
                                    />
                                    <RoleTabs
                                        api={this.api}
                                        domain={domain}
                                        role={role}
                                        selectedName={'review'}
                                    />
                                </PageHeaderDiv>
                                <ReviewList
                                    api={this.api}
                                    domain={domain}
                                    role={role}
                                    roleDetails={roleDetails}
                                    members={roleMembers}
                                    _csrf={_csrf}
                                    isDomainAuditEnabled={isDomainAuditEnabled}
                                    userProfileLink={
                                        this.props.headerDetails.userData
                                            .userLink
                                    }
                                />
                            </RolesContentDiv>
                        </RolesContainerDiv>
                        <UserDomains
                            domains={this.props.domains}
                            api={this.api}
                            domain={domain}
                        />
                    </AppContainerDiv>
                </MainContentDiv>
            </div>
        );
    }
}
