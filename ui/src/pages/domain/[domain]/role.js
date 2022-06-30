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
import RequestUtils from '../../../components/utils/RequestUtils';
import Tabs from '../../../components/header/Tabs';
import Error from '../../_error';
import DomainNameHeader from '../../../components/header/DomainNameHeader';
import {connect} from 'react-redux';
import {getDomainData} from '../../../redux/thunks/domain';
import {getRoles} from '../../../redux/thunks/roles';
import RoleList from '../../../components/role/RoleList';
import {selectIsLoading} from '../../../redux/selectors';
import {selectRoles} from '../../../redux/selectors/roles';
import DomainDetails from '../../../components/header/DomainDetails';
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
        api.getRolePrefix(),
        // api.getMeta(bServicesParamsAll),
        api.getAuthorityAttributes(),
    ]).catch((err) => {
        let response = RequestUtils.errorCheckHelper(err);
        reload = response.reload;
        error = response.error;
        return [{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}];
    });
    // let businessServiceOptionsAll = [];
    // if (domains[2] && domains[2].validValues) {
    //     domains[2].validValues.forEach((businessService) => {
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
    // });
    // }
    return {
        props: {
            reload,
            notFound,
            error,
            userName: context.req.session.shortId,
            domainName: context.query.domain,
            _csrf: domains[0],
            prefixes: domains[1].allPrefixes,
            nonce: context.req.headers.rid,
            // validBusinessServicesAll: businessServiceOptionsAll,
            userAuthorityAttributes: domains[2],
        },
    };
}

class RolePage extends React.Component {
    constructor(props) {
        super(props);
        this.api = API();
    }

    componentDidMount() {
        const {getRoles, domainName, getDomainData, userName} = this.props;
        getDomainData(domainName, userName);
        getRoles(domainName);
    }

    render() {
        const {
            domainName,
            reload,
            roles,
            prefixes,
            _csrf,
            isLoading,
            domainData,
        } = this.props;

        if (reload) {
            window.location.reload();
            return <div/>;
        }
        if (this.props.error) {
            return <Error err={this.props.error}/>;
        }
        return isLoading.length > 0 ? (
            <h1>Loading...</h1>
        ) : (
            <div data-testid='role'>
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
                        <RolesContainerDiv>
                            <RolesContentDiv>
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
                                        api={this.api}
                                        _csrf={_csrf}
                                        validBusinessServices={[]}
                                    />
                                    <Tabs
                                        api={this.api}
                                        domain={domainName}
                                        selectedName={'roles'}
                                        featureFlag={
                                            domainData
                                                ? domainData.featureFlag
                                                : ''
                                        }
                                    />
                                </PageHeaderDiv>
                                <RoleList
                                    api={this.api}
                                    domainName={domainName}
                                    _csrf={_csrf}
                                    prefixes={prefixes}
                                    userAuthorityAttributes={
                                        this.props.userAuthorityAttributes
                                    }
                                />
                            </RolesContentDiv>
                        </RolesContainerDiv>
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
        isLoading: selectIsLoading(state),
        domainData: selectDomainData(state),
        roles: selectRoles(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    getRoles: (domainName) => dispatch(getRoles(domainName)),
    getDomainData: (domainName, userName) =>
        dispatch(getDomainData(domainName, userName)),
});

export default connect(mapStateToProps, mapDispatchToProps)(RolePage);
