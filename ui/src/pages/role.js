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

import DomainDetails from '../components/header/DomainDetails';
import RoleList from '../components/role/RoleList';
import RequestUtils from '../components/utils/RequestUtils';
import Tabs from '../components/header/Tabs';
import Error from './_error';
import { MODAL_TIME_OUT } from '../components/constants/constants';
import createCache from '@emotion/cache';
import { CacheProvider } from '@emotion/react';

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

const TitleDiv = styled.div`
    font: 600 20px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    margin-bottom: 10px;
`;

export default class RolePage extends React.Component {
    static async getInitialProps(props) {
        let api = API(props.req);
        let reload = false;
        let notFound = false;
        let error = undefined;
        var bServicesParams = {
            category: 'domain',
            attributeName: 'businessService',
            userName: props.req.session.shortId,
        };
        var bServicesParamsAll = {
            category: 'domain',
            attributeName: 'businessService',
        };
        const domains = await Promise.all([
            api.listUserDomains(),
            api.getHeaderDetails(),
            api.getDomain(props.query.domain),
            api.getRoles(props.query.domain),
            api.getPendingDomainMembersList(),
            api.getForm(),
            api.isAWSTemplateApplied(props.query.domain),
            api.getRolePrefix(),
            api.getFeatureFlag(),
            api.getMeta(bServicesParams),
            api.getMeta(bServicesParamsAll),
        ]).catch((err) => {
            let response = RequestUtils.errorCheckHelper(err);
            reload = response.reload;
            error = response.error;
            return [{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}];
        });
        let businessServiceOptions = [];
        if (domains[9] && domains[9].validValues) {
            domains[9].validValues.forEach((businessService) => {
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
        let businessServiceOptionsAll = [];
        if (domains[10] && domains[10].validValues) {
            domains[10].validValues.forEach((businessService) => {
                let bServiceOnlyId = businessService.substring(
                    0,
                    businessService.indexOf(':')
                );
                let bServiceOnlyName = businessService.substring(
                    businessService.indexOf(':') + 1
                );
                businessServiceOptionsAll.push({
                    value: bServiceOnlyId,
                    name: bServiceOnlyName,
                });
            });
        }
        let domainDetails = domains[2];
        domainDetails.isAWSTemplateApplied = !!domains[6];
        return {
            api,
            reload,
            notFound,
            error,
            domains: domains[0],
            headerDetails: domains[1],
            domain: domains[2].name,
            domainDetails,
            roles: domains[3],
            users: domains[1],
            pending: domains[4],
            _csrf: domains[5],
            prefixes: domains[7].allPrefixes,
            nonce: props.req.headers.rid,
            featureFlag: domains[8],
            validBusinessServices: businessServiceOptions,
            validBusinessServicesAll: businessServiceOptionsAll,
        };
    }

    constructor(props) {
        super(props);
        this.api = props.api || API();
        this.cache = createCache({
            key: 'athenz',
            nonce: this.props.nonce,
        });
    }

    render() {
        const { domain, reload, domainDetails, roles, users, prefixes, _csrf } =
            this.props;
        if (reload) {
            window.location.reload();
            return <div />;
        }
        if (this.props.error) {
            return <Error err={this.props.error} />;
        }

        return (
            <CacheProvider value={this.cache}>
                <div data-testid='role'>
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
                                        <TitleDiv>{domain}</TitleDiv>
                                        <DomainDetails
                                            domainDetails={domainDetails}
                                            api={this.api}
                                            _csrf={_csrf}
                                            productMasterLink={
                                                this.props.headerDetails
                                                    .productMasterLink
                                            }
                                            validBusinessServices={
                                                this.props.validBusinessServices
                                            }
                                            validBusinessServicesAll={
                                                this.props
                                                    .validBusinessServicesAll
                                            }
                                        />
                                        <Tabs
                                            api={this.api}
                                            domain={domain}
                                            selectedName={'roles'}
                                            featureFlag={this.props.featureFlag}
                                        />
                                    </PageHeaderDiv>
                                    <RoleList
                                        api={this.api}
                                        domain={domain}
                                        roles={roles}
                                        users={users}
                                        _csrf={_csrf}
                                        prefixes={prefixes}
                                        isDomainAuditEnabled={
                                            domainDetails.auditEnabled
                                        }
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
            </CacheProvider>
        );
    }
}
