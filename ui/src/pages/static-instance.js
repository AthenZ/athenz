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
import Header from '../components/header/Header';
import UserDomains from '../components/domain/UserDomains';
import API from '../api';
import styled from '@emotion/styled';
import Head from 'next/head';

import RequestUtils from '../components/utils/RequestUtils';
import Error from './_error';
import createCache from '@emotion/cache';
import { CacheProvider } from '@emotion/react';
import ServiceTabs from '../components/header/ServiceTabs';
import ServiceNameHeader from '../components/header/ServiceNameHeader';
import InstanceList from '../components/service/InstanceList';
import ServiceInstanceDetails from '../components/header/ServiceInstanceDetails';
import { SERVICE_TYPE_STATIC } from '../components/constants/constants';

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

const ServiceContainerDiv = styled.div`
    align-items: stretch;
    flex: 1 1;
    height: calc(100vh - 60px);
    overflow: auto;
    display: flex;
    flex-direction: column;
`;

const ServiceContentDiv = styled.div``;

const PageHeaderDiv = styled.div`
    background: linear-gradient(to top, #f2f2f2, #fff);
    padding: 20px 30px 0;
`;

export default class StaticInstancePage extends React.Component {
    static async getInitialProps(props) {
        let api = API(props.req);
        let reload = false;
        let notFound = false;
        let error = undefined;
        const data = await Promise.all([
            api.listUserDomains(),
            api.getHeaderDetails(),
            api.getDomain(props.query.domain),
            api.getInstances(props.query.domain, props.query.service, 'static'),
            api.getPendingDomainMembersList(),
            api.getForm(),
            api.getServiceHeaderDetails(),
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
            domains: data[0],
            service: props.query.service,
            headerDetails: data[1],
            domainDetails: data[2],
            auditEnabled: data[2].auditEnabled,
            instanceDetails: data[3],
            domain: props.query.domain,
            pending: data[4],
            _csrf: data[5],
            nonce: props.req.headers.rid,
            serviceHeaderDetails: data[6].static,
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
        const {
            domain,
            reload,
            instanceDetails,
            service,
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
        return (
            <CacheProvider value={this.cache}>
                <div data-testid='static-instance'>
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
                            <ServiceContainerDiv>
                                <ServiceContentDiv>
                                    <PageHeaderDiv>
                                        <ServiceNameHeader
                                            domain={domain}
                                            service={service}
                                            serviceHeaderDetails={
                                                this.props.serviceHeaderDetails
                                            }
                                        />
                                        <ServiceInstanceDetails
                                            instanceDetailsMeta={
                                                this.props.instanceDetails
                                                    .workLoadMeta
                                            }
                                            categoryType={SERVICE_TYPE_STATIC}
                                        />
                                        <ServiceTabs
                                            api={this.api}
                                            domain={domain}
                                            service={service}
                                            selectedName={'static'}
                                        />
                                    </PageHeaderDiv>
                                    <InstanceList
                                        category={'static'}
                                        api={this.api}
                                        domain={domain}
                                        _csrf={_csrf}
                                        instances={instanceDetails.workLoadData}
                                        service={this.props.service}
                                    />
                                </ServiceContentDiv>
                            </ServiceContainerDiv>
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
