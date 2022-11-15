/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
import React from 'react';
import Header from '../../components/header/Header';
import UserDomains from '../../components/domain/UserDomains';
import API from '../../api.js';
import styled from '@emotion/styled';
import Head from 'next/head';

import RequestUtils from '../../components/utils/RequestUtils';
import Error from '../_error';
import PendingApprovalTabs from '../../components/pending-approval/PendingApprovalTabs';
import PendingApprovalTable from '../../components/pending-approval/PendingApprovalTable';
import { connect } from 'react-redux';
import { getUserPendingMembers } from '../../redux/thunks/user';
import { CacheProvider } from '@emotion/react';
import createCache from '@emotion/cache';
import { selectIsLoading } from '../../redux/selectors/loading';
import { ReduxPageLoader } from '../../components/denali/ReduxPageLoader';

const HomeContainerDiv = styled.div`
    flex: 1 1;
`;

const WorkFlowSectionDiv = styled.div`
    width: calc(100vw - 25em);
    overflow-x: scroll;
    overflow-y: visible;
    box-sizing: content-box !important;
`;

const TitleDiv = styled.div`
    padding-bottom: 20px;
    font: 600 20px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
`;

const PageHeaderDiv = styled.div`
    background: linear-gradient(to top, #f2f2f2, #fff);
    padding: 20px 30px 0px 30px;
`;

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
    font: 500 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
`;

const WorkFlowDiv = styled.div`
    align-items: stretch;
    flex: 1 1;
    height: calc(100vh - 60px);
    overflow: auto;
    position: relative;
    box-sizing: content-box !important;
`;

export async function getServerSideProps(context) {
    let api = API(context.req);
    let reload = false;
    let error = null;
    const domains = await Promise.all([api.getForm()]).catch((err) => {
        let response = RequestUtils.errorCheckHelper(err);
        reload = response.reload;
        error = response.error;
        return [{}, {}];
    });
    return {
        props: {
            reload,
            error,
            _csrf: domains[0],
            nonce: context.req && context.req.headers.rid,
        },
    };
}

class WorkflowAdmin extends React.Component {
    constructor(props) {
        super(props);
        this.api = API();
        this.cache = createCache({
            key: 'athenz',
            nonce: this.props.nonce,
        });
        this.state = {
            pendingData: props.pendingData,
        };
    }

    componentDidMount() {
        const { getUserPendingMembers } = this.props;
        getUserPendingMembers();
    }

    render() {
        if (this.props.reload) {
            window.location.reload();
            return <div />;
        }
        if (this.props.error) {
            return <Error err={this.props.error} />;
        }
        return this.props.isLoading.length > 0 ? (
            <ReduxPageLoader message={'Loading pending members'} />
        ) : (
            <CacheProvider value={this.cache}>
                <div data-testid='pending-approval'>
                    <Head>
                        <title>Athenz</title>
                    </Head>
                    <Header showSearch={true} />
                    <MainContentDiv>
                        <AppContainerDiv>
                            <HomeContainerDiv>
                                <WorkFlowDiv>
                                    <div>
                                        <PageHeaderDiv>
                                            <TitleDiv>
                                                Pending Items for Approval
                                            </TitleDiv>
                                            <PendingApprovalTabs
                                                selectedName={'admin'}
                                            />
                                        </PageHeaderDiv>

                                        <WorkFlowSectionDiv>
                                            <PendingApprovalTable
                                                _csrf={this.props._csrf}
                                                view={'admin'}
                                            />
                                        </WorkFlowSectionDiv>
                                    </div>
                                </WorkFlowDiv>
                            </HomeContainerDiv>
                            <UserDomains hideDomains={true} />
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
    };
};

const mapDispatchToProps = (dispatch) => ({
    getUserPendingMembers: () => dispatch(getUserPendingMembers()),
});

export default connect(mapStateToProps, mapDispatchToProps)(WorkflowAdmin);
