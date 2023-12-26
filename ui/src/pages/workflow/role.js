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
import Alert from '../../components/denali/Alert.js';

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
import {
    MODAL_TIME_OUT,
    REVIEW_CARDS_SIZE,
    WORKFLOW_TITLE,
} from '../../components/constants/constants.js';
import { getReviewRoles } from '../../redux/thunks/roles.js';
import { selectUserReviewRoles } from '../../redux/selectors/roles.js';
import ReviewCard from '../../components/review/ReviewCard.js';
import Button from '../../components/denali/Button.js';

const HomeContainerDiv = styled.div`
    flex: 1 1;
`;

const WorkFlowSectionDiv = styled.div`
    width: 100%;
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

const StyledDiv = styled.div`
    margin-left: 50px;
    margin-top: 20px;
    display: flex;
`;

const MessageDiv = styled.div`
    display: grid;
    margin-right: 3%;
    align-items: center;
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

class WorkflowRole extends React.Component {
    constructor(props) {
        super(props);
        this.api = API();
        this.onSuccessReview = this.onSuccessReview.bind(this);
        this.handleNextPage = this.handleNextPage.bind(this);
        this.handlePreviousPage = this.handlePreviousPage.bind(this);
        this.cache = createCache({
            key: 'athenz',
            nonce: this.props.nonce,
        });
        this.state = {
            pendingData: props.pendingData,
            justification: '',
            showSuccess: false,
            successMessage: '',
            currentPage: 1,
            totalPages: 1,
        };
    }

    componentDidMount() {
        this.props.getReviewRoles();
    }

    handleNextPage = () => {
        this.setState({
            currentPage: this.state.currentPage + 1,
        });
    };

    handlePreviousPage = () => {
        this.setState({
            currentPage: this.state.currentPage - 1,
        });
    };

    inputChanged(key, evt) {
        this.setState({ [key]: evt.target.value });
    }

    onSuccessReview(successMessage) {
        this.setState({
            showSuccess: true,
            successMessage,
        });
        setTimeout(() => {
            this.setState({
                showSuccess: false,
                successMessage: '',
            });
        }, MODAL_TIME_OUT);
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
        if (this.props.reviewRoles && this.props.reviewRoles.length > 0) {
            this.props.reviewRoles.forEach((role) => {
                reviewCards.push(
                    <ReviewCard
                        category={'role'}
                        key={role.domainName + role.name}
                        domainName={role.domainName}
                        name={role.name}
                        userName={this.props.userName}
                        justification={this.state.justification}
                        _csrf={this.props._csrf}
                        onSuccessReview={this.onSuccessReview}
                    />
                );
            });
        }
        const totalPages =
            Math.ceil(reviewCards.length / REVIEW_CARDS_SIZE) || 1; // Calculate total number of pages
        const { currentPage } = this.state;

        // Calculate the start and end index of the review cards for the current page
        const startIndex = (currentPage - 1) * REVIEW_CARDS_SIZE;
        const endIndex = Math.min(
            startIndex + REVIEW_CARDS_SIZE,
            reviewCards.length
        );

        // Slice the review cards array based on the start and end index
        const paginatedReviewCards = reviewCards.slice(startIndex, endIndex);

        return this.props.isLoading.length > 0 ? (
            <ReduxPageLoader message={'Loading roles to review'} />
        ) : (
            <CacheProvider value={this.cache}>
                <div data-testid='workflow-role-review'>
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
                                                selectedName={'roleReview'}
                                            />
                                        </PageHeaderDiv>
                                        <StyledDiv>
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
                                        </StyledDiv>
                                        <WorkFlowSectionDiv>
                                            {paginatedReviewCards}
                                            {reviewCards.length ? null : (
                                                <StyledDiv>
                                                    No roles to review.
                                                </StyledDiv>
                                            )}
                                            <StyledDiv>
                                                <MessageDiv>
                                                    Displaying page{' '}
                                                    {currentPage} of{' '}
                                                    {totalPages}
                                                </MessageDiv>
                                                {currentPage > 1 && (
                                                    <Button
                                                        secondary
                                                        onClick={
                                                            this
                                                                .handlePreviousPage
                                                        }
                                                    >
                                                        Previous
                                                    </Button>
                                                )}
                                                {currentPage < totalPages && (
                                                    <Button
                                                        secondary
                                                        onClick={
                                                            this.handleNextPage
                                                        }
                                                    >
                                                        Next
                                                    </Button>
                                                )}
                                            </StyledDiv>
                                        </WorkFlowSectionDiv>
                                        {this.state.showSuccess ? (
                                            <Alert
                                                isOpen={this.state.showSuccess}
                                                title={
                                                    this.state.successMessage
                                                }
                                                onClose={this.closeModal}
                                                type='success'
                                            />
                                        ) : null}
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
        reviewRoles: selectUserReviewRoles(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    getReviewRoles: () => dispatch(getReviewRoles()),
});

export default connect(mapStateToProps, mapDispatchToProps)(WorkflowRole);
