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
import RequestUtils from '../../../../../components/utils/RequestUtils';
import RoleTabs from '../../../../../components/header/RoleTabs';
import NameHeader from '../../../../../components/header/NameHeader';
import Error from '../../../../_error';
import createCache from '@emotion/cache';
import {CacheProvider} from '@emotion/react';
import {selectIsLoading} from '../../../../../redux/selectors';
import {
    selectDomainAuditEnabled,
    selectDomainData,
    selectHeaderDetails,
    selectPendingMembersList,
    selectProductMasterLink,
    selectUserLink,
} from '../../../../../redux/selectors/domainData';
import {getDomainData} from '../../../../../redux/thunks/domain';
import {connect} from 'react-redux';
import {selectRole, selectRoleMembers,} from '../../../../../redux/selectors/roles';
import {getRole} from '../../../../../redux/thunks/roles';
import MemberList from '../../../../../components/member/MemberList';

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
    const roles = await Promise.all([
        // api.listUserDomains(),
        // api.getHeaderDetails(),
        // api.getDomain(context.query.domain),
        // api.getRole(
        //     context.query.domain,
        //     context.query.role,
        //     true,
        //     false,
        //     true
        // ),
        // api.getPendingDomainMembersList(),
        api.getForm(),
    ]).catch((err) => {
        let response = RequestUtils.errorCheckHelper(err);
        reload = response.reload;
        error = response.error;
        return [{}];
    });
    return {
        props: {
            reload,
            notFound,
            error,
            // domains: roles[0],
            roleName: context.query.role,
            userName: context.req.session.shortId,
            // members: JsonUtils.omitUndefined(roles[3].roleMembers),
            // headerDetails: roles[1],
            // domainDeails: roles[2],
            // isDomainAuditEnabled: roles[2].auditEnabled,
            // roleDetails: JsonUtils.omitUndefined(roles[3]),
            domainName: context.query.domain,
            // pending: roles[0],
            _csrf: roles[0],
            nonce: context.req.headers.rid,
        },
    };
}

class MemberPage extends React.Component {
    constructor(props) {
        super(props);
        this.api = API();
        this.cache = createCache({
            key: 'athenz',
            nonce: this.props.nonce,
        });
    }

    componentDidMount() {
        const {getRole, getDomainData, domainName, roleName, userName} =
            this.props;
        getDomainData(domainName, userName);
        getRole(domainName, roleName);
    }

    render() {
        const {
            domainName,
            reload,
            members,
            roleName,
            roleDetails,
            isDomainAuditEnabled,
            _csrf,
        } = this.props;
        if (reload) {
            window.location.reload();
            return <div/>;
        }
        if (this.props.error) {
            return <Error err={this.props.error}/>;
        }
        console.log('members are: ', members);
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
                            <RolesContainerDiv>
                                <RolesContentDiv>
                                    <PageHeaderDiv>
                                        <NameHeader
                                            category={'role'}
                                            domain={domainName}
                                            collection={roleName}
                                            collectionDetails={roleDetails}
                                        />
                                        <CollectionDetails
                                            collectionDetails={roleDetails}
                                            api={this.api}
                                            _csrf={_csrf}
                                            productMasterLink={
                                                this.props.productMasterLink
                                            }
                                        />
                                        <RoleTabs
                                            api={this.api}
                                            domain={domainName}
                                            role={roleName}
                                            selectedName={'members'}
                                        />
                                    </PageHeaderDiv>
                                    <MemberList
                                        category={'role'}
                                        api={this.api}
                                        domain={domainName}
                                        collection={roleName}
                                        collectionDetails={roleDetails}
                                        members={members}
                                        _csrf={_csrf}
                                        isDomainAuditEnabled={
                                            isDomainAuditEnabled
                                        }
                                        userProfileLink={this.props.userLink}
                                    />
                                </RolesContentDiv>
                            </RolesContainerDiv>
                            <UserDomains api={this.api} domain={domainName}/>
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
        userLink: selectUserLink(state),
        productMasterLink: selectProductMasterLink(state),
        pending: selectPendingMembersList(state),
        isDomainAuditEnabled: selectDomainAuditEnabled(state),
        headerDetails: selectHeaderDetails(state),
        isLoading: selectIsLoading(state),
        domainDetails: selectDomainData(state),
        roleDetails: selectRole(state, props.roleName),
        members: selectRoleMembers(state, props.roleName),
    };
};

const mapDispatchToProps = (dispatch) => ({
    getDomainData: (domainName, userName) =>
        dispatch(getDomainData(domainName, userName)),
    getRole: (domainName, groupName) =>
        dispatch(getRole(domainName, groupName)),
});

export default connect(mapStateToProps, mapDispatchToProps)(MemberPage);
