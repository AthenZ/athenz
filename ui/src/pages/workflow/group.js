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
import { connect } from 'react-redux';
import { CacheProvider } from '@emotion/react';
import createCache from '@emotion/cache';
import { selectIsLoading } from '../../redux/selectors/loading';
import { ReduxPageLoader } from '../../components/denali/ReduxPageLoader';
import Input from '../../components/denali/Input.js';
import InputLabel from '../../components/denali/InputLabel.js';
import { WORKFLOW_TITLE } from '../../components/constants/constants.js';
import ReviewCard from '../../components/review/ReviewCard.js';
import { getReviewGroups } from '../../redux/thunks/groups.js';
import { selectUserReviewGroups } from '../../redux/selectors/groups.js';

const HomeContainerDiv = styled.div`
    flex: 1 1;
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

const StyledJustification = styled(Input)`
    width: 300px;
    margin-top: 5px;
`;

const StyledInputLabel = styled(InputLabel)`
    margin-top: 5px;
    flex-basis: 20%;
    display: block;
`;

const BusinessJustificationContainer = styled.div`
    margin-left: 50px;
    margin-top: 20px;
    display: flex;
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
            userName: context.req.session.shortId,
        },
    };
}

class WorkflowGroup extends React.Component {
    constructor(props) {
        super(props);
        this.api = API();
        this.cache = createCache({
            key: 'athenz',
            nonce: this.props.nonce,
        });
        this.state = {
            pendingData: props.pendingData,
            justification: '',
        };
    }

    componentDidMount() {
        this.props.getReviewGroups();
    }

    inputChanged(key, evt) {
        this.setState({ [key]: evt.target.value });
    }

    render() {
        if (this.props.reload) {
            window.location.reload();
            return <div />;
        }
        if (this.props.error) {
            return <Error err={this.props.error} />;
        }
        let reviewCards = [];
        if (this.props.reviewGroups && this.props.reviewGroups.length > 0) {
            this.props.reviewGroups.forEach((group) => {
                reviewCards.push(
                    <ReviewCard
                        category={'group'}
                        key={group.domainName + group.name}
                        domainName={group.domainName}
                        name={group.name}
                        userName={this.props.userName}
                        justification={this.state.justification}
                        _csrf={this.props._csrf}
                    />
                );
            });
        }
        return this.props.isLoading.length > 0 ? (
            <ReduxPageLoader message={'Loading groups to review'} />
        ) : (
            <CacheProvider value={this.cache}>
                <div data-testid='workflow-group-review'>
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
                                                selectedName={'groupReview'}
                                            />
                                        </PageHeaderDiv>
                                        <BusinessJustificationContainer>
                                            <StyledInputLabel>
                                                Provide Justification for All
                                                Reviews
                                            </StyledInputLabel>
                                            <StyledJustification
                                                id='all-justification'
                                                name='all-justification'
                                                value={
                                                    this.state.justification
                                                        ? this.state
                                                              .justification
                                                        : ''
                                                }
                                                onChange={this.inputChanged.bind(
                                                    this,
                                                    'justification'
                                                )}
                                                autoComplete={'off'}
                                                placeholder='Enter justification for all here'
                                            />
                                        </BusinessJustificationContainer>
                                        <WorkFlowSectionDiv>
                                            {reviewCards}
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
        reviewGroups: selectUserReviewGroups(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    getReviewGroups: () => dispatch(getReviewGroups()),
});

export default connect(mapStateToProps, mapDispatchToProps)(WorkflowGroup);
