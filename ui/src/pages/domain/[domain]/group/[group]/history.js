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
import Header from '../../../../../components/header/Header';
import UserDomains from '../../../../../components/domain/UserDomains';
import API from '../../../../../api';
import styled from '@emotion/styled';
import Head from 'next/head';

import CollectionDetails from '../../../../../components/header/CollectionDetails';
import CollectionHistoryList from '../../../../../components/history/CollectionHistoryList';
import NameHeader from '../../../../../components/header/NameHeader';
import RequestUtils from '../../../../../components/utils/RequestUtils';
import Error from '../../../../_error';
import GroupTabs from '../../../../../components/header/GroupTabs';
import createCache from '@emotion/cache';
import {CacheProvider} from '@emotion/react';
import JsonUtils from "../../../../../components/utils/JsonUtils";

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

const GroupsContainerDiv = styled.div`
    align-items: stretch;
    flex: 1 1;
    height: calc(100vh - 60px);
    overflow: auto;
    display: flex;
    flex-direction: column;
`;

const GroupsContentDiv = styled.div``;

const PageHeaderDiv = styled.div`
    background: linear-gradient(to top, #f2f2f2, #fff);
    padding: 20px 30px 0;
`;

export async function getServerSideProps(context) {
    let api = API(context.req);
    let reload = false;
    let notFound = false;
    let error = null;
    const historyData = await Promise.all([
        api.listUserDomains(),
        api.getHeaderDetails(),
        api.getDomain(context.query.domain),
        api.getGroup(context.query.domain, context.query.group),
        api.getPendingDomainMembersList(),
        api.getForm(),
    ]).catch((err) => {
        let response = RequestUtils.errorCheckHelper(err);
        reload = response.reload;
        error = response.error;
        return [{}, {}, {}, {}, {}, {}];
    });
    return {
        props: {
            reload,
            notFound,
            error,
            domains: historyData[0],
            domain: context.query.domain,
            collection: context.query.group,
            headerDetails: historyData[1],
            domainDeails: historyData[2],
            auditEnabled: historyData[2].auditEnabled,
            collectionDetails: JsonUtils.omitUndefined(historyData[3]),
            historyrows: JsonUtils.omitUndefined(historyData[3].auditLog),
            pending: historyData[4],
            _csrf: historyData[5],
            nonce: context.req.headers.rid,
        }
    };
}


export default class GroupHistoryPage extends React.Component {
    constructor(props) {
        super(props);
        this.api = API();
        this.cache = createCache({
            key: 'athenz',
            nonce: this.props.nonce,
        });
    }

    render() {
        const {
            domain,
            reload,
            collectionDetails,
            collection,
            historyrows,
            _csrf,
        } = this.props;
        if (reload) {
            window.location.reload();
            return <div/>;
        }
        if (this.props.error) {
            return <Error err={this.props.error}/>;
        }
        return (
            <CacheProvider value={this.cache}>
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
                            <GroupsContainerDiv>
                                <GroupsContentDiv>
                                    <PageHeaderDiv>
                                        <NameHeader
                                            category={'group'}
                                            domain={domain}
                                            collection={collection}
                                            collectionDetails={
                                                collectionDetails
                                            }
                                        />
                                        <CollectionDetails
                                            collectionDetails={
                                                collectionDetails
                                            }
                                            api={this.api}
                                            _csrf={_csrf}
                                            productMasterLink={
                                                this.props.headerDetails
                                                    .productMasterLink
                                            }
                                        />
                                        <GroupTabs
                                            api={this.api}
                                            domain={domain}
                                            group={collection}
                                            selectedName={'history'}
                                        />
                                    </PageHeaderDiv>
                                    <CollectionHistoryList
                                        api={this.api}
                                        domain={domain}
                                        collection={collection}
                                        historyrows={historyrows}
                                        _csrf={_csrf}
                                        category={'group'}
                                    />
                                </GroupsContentDiv>
                            </GroupsContainerDiv>
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
