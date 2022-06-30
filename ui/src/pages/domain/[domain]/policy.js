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
import Header from '../../../components/header/Header';
import UserDomains from '../../../components/domain/UserDomains';
import API from '../../../api';
import styled from '@emotion/styled';
import Head from 'next/head';

import DomainDetails from '../../../components/header/DomainDetails';
import RequestUtils from '../../../components/utils/RequestUtils';
import Tabs from '../../../components/header/Tabs';
import Error from '../../_error';
import createCache from '@emotion/cache';
import { CacheProvider } from '@emotion/react';
import DomainNameHeader from '../../../components/header/DomainNameHeader';
import { getDomainData } from '../../../redux/thunks/domain';
import { connect } from 'react-redux';
import { getPolicies } from '../../../redux/thunks/policies';
import PolicyList from '../../../components/policy/PolicyList';
import { getRoles } from '../../../redux/thunks/roles';
import { selectIsLoading } from '../../../redux/selectors';
import { selectDomainData } from '../../../redux/selectors/domainData';

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
    var bServicesParams = {
        category: 'domain',
        attributeName: 'businessService',
        userName: context.req.session.shortId,
    };
    var bServicesParamsAll = {
        category: 'domain',
        attributeName: 'businessService',
    };
    const domains = await Promise.all([
        // api.listUserDomains(),
        // api.getHeaderDetails(),
        // api.getDomain(context.query.domain),
        // api.getPolicies(context.query.domain, false, true),
        api.getForm(),
        // api.getPendingDomainMembersList(),
        // api.isAWSTemplateApplied(context.query.domain),
        // api.getFeatureFlag(),
        // api.getMeta(bServicesParams),
        api.getMeta(bServicesParamsAll),
        // api.getPendingDomainMembersCountByDomain(context.query.domain),
    ]).catch((err) => {
        let response = RequestUtils.errorCheckHelper(err);
        reload = response.reload;
        error = response.error;
        return [{}, {}];
    });
    // let businessServiceOptions = [];
    // if (domains[8] && domains[8].validValues) {
    //     domains[8].validValues.forEach((businessService) => {
    //         let bServiceOnlyId = businessService.substring(
    //             0,
    //             businessService.indexOf(':')
    //         );
    //         let bServiceOnlyName = businessService.substring(
    //             businessService.indexOf(':') + 1
    //         );
    //         businessServiceOptions.push({
    //             value: bServiceOnlyId,
    //             name: bServiceOnlyName,
    //         });
    //     });
    // }
    let businessServiceOptionsAll = [];
    if (domains[1] && domains[1].validValues) {
        domains[1].validValues.forEach((businessService) => {
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
    return {
        props: {
            reload,
            notFound,
            error,
            userName: context.req.session.shortId,
            domainName: context.query.domain,
            _csrf: domains[0],
            nonce: context.req.headers.rid,
            validBusinessServicesAll: businessServiceOptionsAll,
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
    }

    componentWillMount() {
        const { getPolicies, domainName, getDomainData, userName, getRoles } =
            this.props;
        getDomainData(domainName, userName);
        getPolicies(domainName);
        getRoles(domainName);
    }

    render() {
        const { domainName, reload, isLoading, domainData, _csrf } = this.props;
        if (reload) {
            window.location.reload();
            return <div />;
        }
        if (this.props.error) {
            return <Error err={this.props.error} />;
        }

        return isLoading.length !== 0 ? (
            <h1>Loading...</h1>
        ) : (
            <CacheProvider value={this.cache}>
                <div data-testid='policy'>
                    <Head>
                        <title>Athenz</title>
                    </Head>
                    <Header
                        showSearch={true}
                        headerDetails={domainData.headerDetails}
                        pending={domainData.pendingMembersList}
                    />
                    <MainContentDiv>
                        <AppContainerDiv>
                            <PoliciesContainerDiv>
                                <PoliciesContentDiv>
                                    <PageHeaderDiv>
                                        <DomainNameHeader
                                            domainName={domainData.name}
                                            pendingCount={
                                                domainData.pendingMembersList
                                                    ? domainData
                                                        .pendingMembersList
                                                        .length
                                                    : 0
                                            }
                                        />
                                        <DomainDetails
                                            domainDetails={
                                                domainData.domainDetails || {}
                                            }
                                            api={this.api}
                                            _csrf={_csrf}
                                            productMasterLink={
                                                domainData.headerDetails
                                                    ? domainData.headerDetails
                                                        .productMasterLink
                                                    : ''
                                            }
                                            validBusinessServices={
                                                domainData
                                                    ? domainData.businessData
                                                    : ''
                                            }
                                            validBusinessServicesAll={
                                                this.props
                                                    .validBusinessServicesAll
                                            }
                                        />
                                        <Tabs
                                            api={this.api}
                                            domain={domainName}
                                            selectedName={'policies'}
                                            featureFlag={
                                                domainData.featureFlag || ''
                                            }
                                        />
                                    </PageHeaderDiv>
                                    <PolicyList
                                        api={this.api}
                                        domain={domainName}
                                        _csrf={_csrf}
                                    />
                                </PoliciesContentDiv>
                            </PoliciesContainerDiv>
                            <UserDomains api={this.api} domain={domainName} />
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
        domainData: selectDomainData(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    getPolicies: (domainName) => dispatch(getPolicies(domainName, true, true)),
    getDomainData: (domainName, userName) =>
        dispatch(getDomainData(domainName, userName)),
    getRoles: (domainName) => dispatch(getRoles(domainName)),
});

export default connect(mapStateToProps, mapDispatchToProps)(PolicyPage);
