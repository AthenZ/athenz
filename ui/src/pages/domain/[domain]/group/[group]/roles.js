// getDomainRoleMember
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
import NameHeader from '../../../../../components/header/NameHeader';
import Error from '../../../../_error';
import GroupTabs from '../../../../../components/header/GroupTabs';
import GroupRoleTable from '../../../../../components/group/GroupRoleTable';
import SearchInput from '../../../../../components/denali/SearchInput';
import {getDomainData} from '../../../../../redux/thunks/domain';
import {getDomainRoleMembers, getGroup,} from '../../../../../redux/thunks/groups';
import {connect} from 'react-redux';
import {selectIsLoading} from '../../../../../redux/selectors';
import {selectGroup, selectGroupRoleMembers,} from '../../../../../redux/selectors/group';
import {selectDomainData} from '../../../../../redux/selectors/domainData';

const AppContainerDiv = styled.div`
    align-items: stretch;
    flex-flow: row nowrap;
    height: 100%;
    display: flex;
    justify-content: flex-start;
`;

const StyledSearchInputDiv = styled.div`
    width: 50%;
    margin-top: 20px;
    margin-left: 30px;
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
const ContainerDiv = styled.div`
    padding-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-flow: row nowrap;
`;

const TableDiv = styled.div`
    width: 95%;
    justify-content: space-between;
    padding-left: 2%;
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
    const details = await Promise.all([api.getForm()]).catch((err) => {
        let response = RequestUtils.errorCheckHelper(err);
        reload = response.reload;
        error = response.error;
        return [{}, {}, {}, {}, {}, {}, {}];
    });
    return {
        props: {
            reload,
            notFound,
            error,
            groupName: context.query.group,
            domainName: context.query.domain,
            _csrf: details[0],
            nonce: context.req.headers.rid,
        },
    };
}

class GroupRolesPage extends React.Component {
    constructor(props) {
        super(props);
        this.api = API();
        this.state = {
            searchText: '',
        };
    }

    componentDidMount() {
        const {
            domainName,
            userName,
            groupName,
            getDomainData,
            getGroup,
            getDomainRoleMembers,
        } = this.props;
        getDomainData(domainName, userName);
        getGroup(domainName, groupName);
        getDomainRoleMembers(domainName, groupName);
    }

    componentDidUpdate = (prevProps) => {
        if (prevProps.domain !== this.props.domain) {
            this.setState({
                searchText: '',
            });
        }
    };

    render() {
        const {
            domainName,
            domainData,
            roleMembers,
            reload,
            groupDetails,
            groupName,
            _csrf,
            isLoading,
        } = this.props;

        if (reload) {
            window.location.reload();
            return <div/>;
        }
        if (this.props.error) {
            return <Error err={this.props.error}/>;
        }

        let roles = roleMembers ? roleMembers.memberRoles : [];
        if (this.state.searchText.trim() !== '') {
            roles = roleMembers.memberRoles.filter((role) => {
                return role.roleName.includes(this.state.searchText.trim());
            });
        }
        let displayData = roles && roles.length > 0;
        return isLoading.length !== 0 ? (
            <h1>Loading...</h1>
        ) : (
            <div data-testid='group-role'>
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
                                        category={'group'}
                                        domain={domainName}
                                        collection={groupName}
                                        collectionDetails={
                                            groupDetails ? groupDetails : {}
                                        }
                                    />
                                    <CollectionDetails
                                        collectionDetails={
                                            groupDetails ? groupDetails : {}
                                        }
                                        api={this.api}
                                        _csrf={_csrf}
                                        productMasterLink={
                                            domainData.headerDetails
                                                ? domainData.headerDetails
                                                    .productMasterLink
                                                : ''
                                        }
                                    />
                                    <GroupTabs
                                        api={this.api}
                                        domain={domainName}
                                        group={groupName}
                                        selectedName={'roles'}
                                    />
                                </PageHeaderDiv>
                                <ContainerDiv>
                                    <StyledSearchInputDiv>
                                        <SearchInput
                                            dark={false}
                                            name='search'
                                            fluid={true}
                                            value={this.state.searchText}
                                            placeholder={
                                                this.state.showuser
                                                    ? 'Enter user name'
                                                    : 'Enter role name'
                                            }
                                            error={this.state.error}
                                            onChange={(event) =>
                                                this.setState({
                                                    searchText:
                                                    event.target.value,
                                                    error: false,
                                                })
                                            }
                                        />
                                    </StyledSearchInputDiv>
                                </ContainerDiv>
                                <TableDiv>
                                    <GroupRoleTable
                                        api={this.api}
                                        domain={this.domainName}
                                        roles={roles}
                                        prefixes={
                                            roleMembers
                                                ? roleMembers.prefix
                                                : ''
                                        }
                                        searchText={this.state.searchText}
                                        displayTable={displayData}
                                    />
                                </TableDiv>
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
        domainData: selectDomainData(state),
        isLoading: selectIsLoading(state),
        groupDetails: selectGroup(state, props.groupName),
        roleMembers: selectGroupRoleMembers(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    getDomainData: (domainName, userName) =>
        dispatch(getDomainData(domainName, userName)),
    getGroup: (domainName, groupName) =>
        dispatch(getGroup(domainName, groupName)),
    getDomainRoleMembers: (domainName, gropName) =>
        dispatch(getDomainRoleMembers(domainName, gropName)),
});

export default connect(
    mapStateToProps,
    mapDispatchToProps
)(GroupRolesPage);
