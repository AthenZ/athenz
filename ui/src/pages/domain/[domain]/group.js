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
import DomainNameHeader from '../../../components/header/DomainNameHeader';
import {connect} from 'react-redux';
import {getDomainData} from '../../../redux/thunks/domain';
import {getGroups} from '../../../redux/thunks/groups';
import GroupList from '../../../components/group/GroupList';
import {selectIsLoading} from '../../../redux/selectors';
import {selectDomainData} from '../../../redux/selectors/domainData';

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
    var bServicesParamsAll = {
        category: 'domain',
        attributeName: 'businessService',
    };
    const domains = await Promise.all([
        api.getForm(),
        // api.isAWSTemplateApplied(context.query.domain),
        // api.getMeta(bServicesParamsAll),
    ]).catch((err) => {
        let response = RequestUtils.errorCheckHelper(err);
        reload = response.reload;
        error = response.error;
        return [{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}];
    });
    // let businessServiceOptionsAll = [];
    // if (domains[1] && domains[1].validValues) {
    //     domains[1].validValues.forEach((businessService) => {
    //         let bServiceOnlyId = businessService.substring(
    //             0,
    //             businessService.indexOf(':')
    //         );
    //         let bServiceOnlyName = businessService.substring(
    //             businessService.indexOf(':') + 1
    //         );
    //         businessServiceOptionsAll.push({
    //             value: bServiceOnlyId,
    //             name: bServiceOnlyName,
    //         });
    //     });
    // }
    return {
        props: {
            reload,
            notFound,
            error,
            domainName: context.query.domain,
            userName: context.req.session.shortId,
            _csrf: domains[0],
            nonce: context.req.headers.rid,
            // validBusinessServicesAll: businessServiceOptionsAll,
        },
    };
}

class GroupPage extends React.Component {
    constructor(props) {
        super(props);
        this.api = API();
    }

    componentDidMount() {
        const {getDomainData, getGroupsList, domainName, userName} =
            this.props;
        getDomainData(domainName, userName);
        getGroupsList(domainName);
    }

    render() {
        const {reload, _csrf, domainData, isLoading, domainName} = this.props;
        if (reload) {
            console.log('reload', reload);
            window.location.reload();
            return <div/>;
        }
        if (this.props.error) {
            return <Error err={this.props.error}/>;
        }
        return isLoading.length !== 0 ? (
            <h1>Loading...</h1>
        ) : (
            <div data-testid='group'>
                <Head>
                    <title>Athenz</title>
                </Head>
                <Header
                    showSearch={true}
                    headerDetails={domainData.headerDetails}
                    pending={this.props.pending}
                />
                <MainContentDiv>
                    <AppContainerDiv>
                        <GroupsContainerDiv>
                            <GroupsContentDiv>
                                <PageHeaderDiv>
                                    <DomainNameHeader
                                        domainName={domainName}
                                        pendingCount={
                                            domainData.pendingMembersList
                                                ? domainData.pendingMembersList
                                                    .length
                                                : 0
                                        }
                                    />
                                    <DomainDetails
                                        domainDetails={
                                            domainData ? domainData : {}
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
                                            domainData.businessData
                                        }
                                        validBusinessServicesAll={
                                            this.props.validBusinessServicesAll
                                        }
                                    />
                                    <Tabs
                                        api={this.api}
                                        domain={domainName}
                                        selectedName={'groups'}
                                        featureFlag={domainData.featureFlag}
                                    />
                                </PageHeaderDiv>
                                <GroupList
                                    api={this.api}
                                    domain={domainName}
                                    _csrf={_csrf}
                                    isDomainAuditEnabled={
                                        domainData.auditEnabled
                                    }
                                    userProfileLink={
                                        domainData.headerDetails
                                            ? domainData.headerDetails.userData
                                                .userLink
                                            : ''
                                    }
                                />
                            </GroupsContentDiv>
                        </GroupsContainerDiv>
                        <UserDomains api={this.api} domain={domainName}/>
                    </AppContainerDiv>
                </MainContentDiv>
            </div>
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        domainData: selectDomainData(state),
        isLoading: selectIsLoading(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    getDomainData: (domainName, userName) =>
        dispatch(getDomainData(domainName, userName)),
    getGroupsList: (domainName) => dispatch(getGroups(domainName)),
});

export default connect(mapStateToProps, mapDispatchToProps)(GroupPage);
