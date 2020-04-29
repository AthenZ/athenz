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
import DomainDetails from '../components/header/DomainDetails';
import HistoryList from '../components/history/HistoryList';
import Tabs from '../components/header/Tabs';
import RequestUtils from '../components/utils/RequestUtils';
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

export default class HistoryPage extends React.Component {
    static async getInitialProps(props) {
        let api = API(props.req);
        let reload = false;
        let notFound = false;
        let error = undefined;
        const historyData = await Promise.all([
            api.listUserDomains(),
            api.getHeaderDetails(),
            api.getDomain(props.query.domain),
            api.getHistory(props.query.domain, 'ALL', null, null),
            api.getRoles(props.query.domain),
            api.getForm(),
            api.getPendingDomainRoleMembersList(),
            api.isAWSTemplateApplied(props.query.domain),
        ]).catch((err) => {
            let response = RequestUtils.errorCheckHelper(err);
            reload = response.reload;
            error = response.error;
            return [{}, {}, {}, {}, {}, {}, {}, {}];
        });
        let domainDetails = historyData[2];
        domainDetails.isAWSTemplateApplied = !!historyData[7];
        return {
            api,
            reload,
            notFound,
            error,
            domains: historyData[0],
            headerDetails: historyData[1],
            domain: props.query.domain,
            domainDetails: domainDetails,
            historyrows: historyData[3],
            roles: historyData[4],
            _csrf: historyData[5],
            pending: historyData[6],
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
            domainDetails,
            historyrows,
            roles,
            _csrf,
        } = this.props;
        if (reload) {
            window.location.reload();
            return <div />;
        }
        if (this.props.error) {
            return <Error err={this.props.error} />;
        }
        return (
            <div data-testid='history'>
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
                        <HistoryContainerDiv>
                            <HistoryContentDiv>
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
                                    />
                                    <Tabs
                                        api={this.api}
                                        domain={domain}
                                        selectedName={'history'}
                                    />
                                </PageHeaderDiv>
                                <HistoryList
                                    api={this.api}
                                    domain={domain}
                                    roles={roles}
                                    historyrows={historyrows}
                                    _csrf={_csrf}
                                />
                            </HistoryContentDiv>
                        </HistoryContainerDiv>
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
