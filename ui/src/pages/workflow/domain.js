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
import InputDropdown from '../../components/denali/InputDropdown';
import { withRouter } from 'next/router';
import { WORKFLOW_DOMAIN_VIEW_DROPDOWN_PLACEHOLDER, WORKFLOW_TITLE } from '../../components/constants/constants';
import PageUtils from '../../components/utils/PageUtils';
import { selectIsLoading } from '../../redux/selectors/loading';
import { connect } from 'react-redux';
import {
    getAllDomainsList,
    getPendingDomainMembersListByDomain,
} from '../../redux/thunks/domains';
import { selectAllDomainsList } from '../../redux/selectors/domains';
import PendingApprovalTable from '../../components/pending-approval/PendingApprovalTable';
import createCache from '@emotion/cache';
import { CacheProvider } from '@emotion/react';
import { ReduxPageLoader } from '../../components/denali/ReduxPageLoader';

const HomeContainerDiv = styled.div`
    flex: 1 1;
`;
const StyledSearchInputDiv = styled.div`
    width: 460px;
`;
const WorkFlowSectionDiv = styled.div`
    width: calc(100vw - 15em);
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
    font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
`;

const WorkFlowDiv = styled.div`
    align-items: stretch;
    flex: 1 1;
    height: calc(100vh - 60px);
    overflow: auto;
    position: relative;
`;

const StyledInputDropdown = styled(InputDropdown)`
    padding-top: 15px;
    padding-left: 30px;
`;

export async function getServerSideProps(context) {
    let api = API(context.req);
    let reload = false;
    let error = null;
    let requestedDomain = context.req.query.domain || null;
    const domains = await Promise.all([api.getForm()]).catch((err) => {
        let response = RequestUtils.errorCheckHelper(err);
        reload = response.reload;
        error = response.error;
        return [{}];
    });
    return {
        props: {
            reload,
            error,
            userName: context.req.session.shortId,
            _csrf: domains[0],
            nonce: context.req && context.req.headers.rid,
            selectedDomain: requestedDomain,
        },
    };
}

class WorkflowDomain extends React.Component {
    constructor(props) {
        super(props);
        this.changeDomain = this.changeDomain.bind(this);
        this.loadPendingMembers = this.loadPendingMembers.bind(this);
        this.state = {
            selectedDomain:
                this.props.selectedDomain === 'ALL'
                    ? null
                    : this.props.selectedDomain,
            error: this.props.error,
        };
        this.cache = createCache({
            key: 'athenz',
            nonce: this.props.nonce,
        });
    }

    changeDomain(chosen) {
        if (chosen) {
            this.setState({
                selectedDomain: chosen.name,
            });
        } else {
            this.setState({
                selectedDomain: null,
            });
        }
    }

    componentDidMount() {
        const { getAllDomainsList } = this.props;
        getAllDomainsList();
        this.loadPendingMembers();
    }

    componentDidUpdate(prevProps, prevState, snapshot) {
        if (prevState.selectedDomain !== this.state.selectedDomain) {
            this.props.router.replace(
                {
                    pathname: PageUtils.workflowDomainPage(),
                    query: { domain: this.state.selectedDomain },
                },
                undefined,
                { shallow: true }
            );
            this.loadPendingMembers();
        }
    }

    loadPendingMembers() {
        this.props
            .getPendingDomainMembersListByDomain(this.state.selectedDomain)
            .then(() => {
                this.setState({
                    error: null,
                });
            })
            .catch((err) => {
                this.setState({
                    error: RequestUtils.errorCheckHelper(err).error,
                });
            });
    }

    render() {
        if (this.props.reload) {
            window.location.reload();
            return <div />;
        }
        if (this.state.error !== null) {
            return <Error err={this.state.error} />;
        }
        return this.props.isLoading.length > 0 ? (
            <ReduxPageLoader message={'Loading data'} />
        ) : (
            <CacheProvider value={this.cache}>
                <div data-testid='domain-pending-approval'>
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
                                                {WORKFLOW_TITLE}
                                            </TitleDiv>
                                            <PendingApprovalTabs
                                                selectedName={'domain'}
                                            />
                                        </PageHeaderDiv>
                                        <WorkFlowSectionDiv>
                                            <StyledSearchInputDiv>
                                                <StyledInputDropdown
                                                    name='domains-inputd'
                                                    id={'domains-inputdropdown'}
                                                    defaultSelectedValue={
                                                        this.state
                                                            .selectedDomain
                                                    }
                                                    options={
                                                        this.props.allDomainList
                                                    }
                                                    onChange={this.changeDomain}
                                                    placeholder={
                                                        WORKFLOW_DOMAIN_VIEW_DROPDOWN_PLACEHOLDER
                                                    }
                                                    filterable
                                                    noclear={false}
                                                    fluid
                                                />
                                            </StyledSearchInputDiv>
                                            <PendingApprovalTable
                                                // we send , because it is illegal domain, and we don't want to enter the undefined case in the selector
                                                domainName={
                                                    this.state.selectedDomain ||
                                                    ','
                                                }
                                                loadList={
                                                    this.loadPendingMembers
                                                }
                                                _csrf={this.props._csrf}
                                                view={'domain'}
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
        allDomainList: selectAllDomainsList(state),
        isLoading: selectIsLoading(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    getAllDomainsList: () => dispatch(getAllDomainsList()),
    getPendingDomainMembersListByDomain: (domainName) =>
        dispatch(getPendingDomainMembersListByDomain(domainName)),
});

export default connect(
    mapStateToProps,
    mapDispatchToProps
)(withRouter(WorkflowDomain));
