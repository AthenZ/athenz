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
import { getGroup } from '../../../../../redux/thunks/groups';
import { connect } from 'react-redux';
import { getDomainData } from '../../../../../redux/thunks/domain';
import MemberList from '../../../../../components/member/MemberList';
import { selectIsLoading } from '../../../../../redux/selectors/loading';
import { selectDomainAuditEnabled } from '../../../../../redux/selectors/domainData';
import {
    selectGroup,
    selectGroupMembers,
} from '../../../../../redux/selectors/groups';
import createCache from '@emotion/cache';
import { CacheProvider } from '@emotion/react';
import { ReduxPageLoader } from '../../../../../components/denali/ReduxPageLoader';
import { getAllUsers } from '../../../../../redux/thunks/user';
import { selectAllUsers } from '../../../../../redux/selectors/user';

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
    const groups = await Promise.all([api.getForm()]).catch((err) => {
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
            groupName: context.query.group,
            domainName: context.query.domain,
            userName: context.req.session.shortId,
            _csrf: groups[0],
            nonce: context.req.headers.rid,
        },
    };
}

class GroupMemberPage extends React.Component {
    constructor(props) {
        super(props);
        this.cache = createCache({
            key: 'athenz',
            nonce: this.props.nonce,
        });
        this.state = {
            error: null,
            reload: false,
        };
    }

    componentDidMount() {
        const {
            getAllUsers,
            domainName,
            userName,
            getDomainData,
            groupName,
            getGroup,
        } = this.props;
        Promise.all([
            getAllUsers(),
            getDomainData(domainName, userName),
            getGroup(domainName, groupName),
        ]).catch((err) => {
            let response = RequestUtils.errorCheckHelper(err);
            this.setState({
                error: response.error,
                reload: response.reload,
            });
        });
    }

    render() {
        const {
            domainName,
            reload,
            groupName,
            _csrf,
            groupDetails,
            isLoading,
        } = this.props;
        if (reload || this.state.reload) {
            window.location.reload();
            return <div />;
        }
        const err = this.props.error || this.state.error;
        if (err) {
            return <Error err={err} />;
        }

        return isLoading.includes('getDomainData') ? (
            <ReduxPageLoader message={'Loading domain data'} />
        ) : (
            <CacheProvider value={this.cache}>
                <div data-testid='group-members'>
                    <Head>
                        <title>Athenz</title>
                    </Head>
                    <Header showSearch={true} />
                    <MainContentDiv>
                        <AppContainerDiv>
                            <GroupsContainerDiv>
                                <GroupsContentDiv>
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
                                            _csrf={_csrf}
                                        />
                                        <GroupTabs
                                            domain={domainName}
                                            group={groupName}
                                            selectedName={'members'}
                                        />
                                    </PageHeaderDiv>
                                    <MemberList
                                        category={'group'}
                                        domain={domainName}
                                        collection={groupName}
                                        collectionDetails={groupDetails}
                                        members={this.props.members}
                                        _csrf={_csrf}
                                        isDomainAuditEnabled={
                                            this.props.auditEnabled
                                        }
                                    />
                                </GroupsContentDiv>
                            </GroupsContainerDiv>
                            <UserDomains domain={domainName} />
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
        auditEnabled: selectDomainAuditEnabled(state),
        groupDetails: selectGroup(state, props.domainName, props.groupName),
        members: selectGroupMembers(state, props.domainName, props.groupName),
        userList: selectAllUsers(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    getAllUsers: () => dispatch(getAllUsers()),
    getDomainData: (domainName, userName) =>
        dispatch(getDomainData(domainName, userName)),
    getGroup: (domainName, groupName) =>
        dispatch(getGroup(domainName, groupName)),
});

export default connect(mapStateToProps, mapDispatchToProps)(GroupMemberPage);
