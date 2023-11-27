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
import CollectionHistoryList from '../../../../../components/history/CollectionHistoryList';
import NameHeader from '../../../../../components/header/NameHeader';
import RequestUtils from '../../../../../components/utils/RequestUtils';
import Error from '../../../../_error';
import GroupTabs from '../../../../../components/header/GroupTabs';
import { getDomainData } from '../../../../../redux/thunks/domain';
import { getGroupHistory } from '../../../../../redux/thunks/groups';
import { connect } from 'react-redux';
import { selectIsLoading } from '../../../../../redux/selectors/loading';
import {
    selectGroup,
    selectGroupHistory,
} from '../../../../../redux/selectors/groups';
import createCache from '@emotion/cache';
import { CacheProvider } from '@emotion/react';
import { ReduxPageLoader } from '../../../../../components/denali/ReduxPageLoader';

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
    const historyData = await Promise.all([api.getForm()]).catch((err) => {
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
            domainName: context.query.domain,
            groupName: context.query.group,
            userName: context.req.session.shortId,
            _csrf: historyData[0],
            nonce: context.req.headers.rid,
        },
    };
}

class GroupHistoryPage extends React.Component {
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
            domainName,
            userName,
            getDomainData,
            groupName,
            getGroupHistory,
        } = this.props;
        Promise.all([
            getDomainData(domainName, userName),
            getGroupHistory(domainName, groupName),
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
            isLoading,
            collectionDetails,
            historyrows,
            _csrf,
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
                <div data-testid='member'>
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
                                                collectionDetails
                                                    ? collectionDetails
                                                    : {}
                                            }
                                        />
                                        <CollectionDetails
                                            collectionDetails={
                                                collectionDetails
                                                    ? collectionDetails
                                                    : {}
                                            }
                                            _csrf={_csrf}
                                        />
                                        <GroupTabs
                                            domain={domainName}
                                            group={groupName}
                                            selectedName={'history'}
                                        />
                                    </PageHeaderDiv>
                                    <CollectionHistoryList
                                        domain={domainName}
                                        collection={groupName}
                                        historyrows={historyrows}
                                        _csrf={_csrf}
                                        category={'group'}
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
        collectionDetails: selectGroup(
            state,
            props.domainName,
            props.groupName
        ),
        historyrows: selectGroupHistory(
            state,
            props.domainName,
            props.groupName
        ),
    };
};

const mapDispatchToProps = (dispatch) => ({
    getDomainData: (domainName, userName) =>
        dispatch(getDomainData(domainName, userName)),
    getGroupHistory: (domainName, groupName) =>
        dispatch(getGroupHistory(domainName, groupName)),
});

export default connect(mapStateToProps, mapDispatchToProps)(GroupHistoryPage);
