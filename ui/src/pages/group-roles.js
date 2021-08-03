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
import Header from '../components/header/Header';
import UserDomains from '../components/domain/UserDomains';
import API from '../api';
import styled from '@emotion/styled';
import Head from 'next/head';

import CollectionDetails from '../components/header/CollectionDetails';
import RequestUtils from '../components/utils/RequestUtils';
import NameHeader from '../components/header/NameHeader';
import Error from './_error';
import GroupTabs from '../components/header/GroupTabs';
import GroupRoleTable from '../components/group/GroupRoleTable';
import SearchInput from '../components/denali/SearchInput';
import createCache from '@emotion/cache';
import { CacheProvider } from '@emotion/react';

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

export default class GroupRolesPage extends React.Component {
    static async getInitialProps(props) {
        let api = API(props.req);
        let reload = false;
        let notFound = false;
        let error = undefined;
        const details = await Promise.all([
            api.listUserDomains(),
            api.getHeaderDetails(),
            api.getDomain(props.query.domain),
            api.getDomainRoleMembers(
                props.query.domain + ':group.' + props.query.group
            ),
            api.getPendingDomainMembersList(),
            api.getForm(),
            api.getGroup(props.query.domain, props.query.group),
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
            domains: details[0],
            group: props.query.group,
            headerDetails: details[1],
            domainDetails: details[2],
            groupDetails: details[6],
            roles: details[3].memberRoles,
            prefix: details[3].prefix,
            domain: props.query.domain,
            pending: details[4],
            _csrf: details[5],
            nonce: props.req.headers.rid,
        };
    }

    constructor(props) {
        super(props);
        this.api = props.api || API();
        this.cache = createCache({
            key: 'athenz',
            nonce: this.props.nonce,
        });
        this.state = {
            searchText: '',
            roles: props.roles || [],
        };
    }

    componentDidUpdate = (prevProps) => {
        if (prevProps.domain !== this.props.domain) {
            this.setState({
                roles: this.props.roles,
                searchText: '',
            });
        }
    };

    render() {
        const { domain, reload, groupDetails, group, prefix, _csrf } =
            this.props;
        if (reload) {
            window.location.reload();
            return <div />;
        }
        if (this.props.error) {
            return <Error err={this.props.error} />;
        }

        let roles = this.state.roles;

        if (this.state.searchText.trim() !== '') {
            roles = this.state.roles.filter((role) => {
                return role.roleName.includes(this.state.searchText.trim());
            });
        }
        let displayData = this.state.roles && this.state.roles.length > 0;
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
                                            category={'group'}
                                            domain={domain}
                                            collection={group}
                                            collectionDetails={groupDetails}
                                        />
                                        <CollectionDetails
                                            collectionDetails={groupDetails}
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
                                            group={group}
                                            selectedName={'roles'}
                                        />
                                    </PageHeaderDiv>
                                    {displayData && (
                                        <ContainerDiv>
                                            <StyledSearchInputDiv>
                                                <SearchInput
                                                    dark={false}
                                                    name='search'
                                                    fluid={true}
                                                    value={
                                                        this.state.searchText
                                                    }
                                                    placeholder={
                                                        this.state.showuser
                                                            ? 'Enter user name'
                                                            : 'Enter role name'
                                                    }
                                                    error={this.state.error}
                                                    onChange={(event) =>
                                                        this.setState({
                                                            searchText:
                                                                event.target
                                                                    .value,
                                                            error: false,
                                                        })
                                                    }
                                                />
                                            </StyledSearchInputDiv>
                                        </ContainerDiv>
                                    )}
                                    <TableDiv>
                                        <GroupRoleTable
                                            api={this.api}
                                            domain={this.domain}
                                            roles={roles}
                                            prefixes={prefix}
                                            searchText={this.state.searchText}
                                            displayTable={displayData}
                                        />
                                    </TableDiv>
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
