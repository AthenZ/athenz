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
import styled from '@emotion/styled';
import GroupReviewTable from '../group/GroupReviewTable';
import ReviewTable from './ReviewTable';
import Alert from '../denali/Alert';
import { MODAL_TIME_OUT } from '../constants/constants';
import { selectIsLoading } from '../../redux/selectors/loading';
import { selectTimeZone } from '../../redux/selectors/domains';
import { connect } from 'react-redux';
import { ReduxPageLoader } from '../denali/ReduxPageLoader';
import { withRouter } from 'next/router';

const RolesSectionDiv = styled.div`
    margin: 20px;
    margin-bottom: 0px;
`;

// dont need to make it as redux because it get props from groups and role and in order to not need to figure out
// which data to get from the store it easier to get the data from the father component which is seperated between roles and groups
class ReviewList extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            showuser: false,
            members: props.members || [],
            errorMessage: null,
        };
        this.closeModal = this.closeModal.bind(this);
        this.submitSuccess = this.submitSuccess.bind(this);
    }

    componentDidUpdate = (prevProps) => {
        if (
            prevProps.collection !== this.props.collection ||
            prevProps.domain !== this.props.domain
        ) {
            this.setState({
                members: this.props.members,
                showuser: false,
            });
        }
    };

    submitSuccess(successMessage) {
        this.setState({
            showSuccess: true,
            successMessage,
            errorMessage: null,
        });
        this.props.onSuccessReview &&
            this.props.onSuccessReview(successMessage + ` Removed ${this.props.category} from view.`);
        setTimeout(() => {
            this.setState({
                showSuccess: false,
            });
            if (!this.props.isCardView) {
                this.props.router.push(
                    `/domain/${this.props.domain}/${this.props.category}/${this.props.collection}/members`,
                    `/domain/${this.props.domain}/${this.props.category}/${this.props.collection}/members`
                );
            }
        }, MODAL_TIME_OUT);
    }

    closeModal() {
        this.setState({ showSuccess: null });
    }

    render() {
        const { domain, collection, collectionDetails } = this.props;
        return this.props.isLoading.length !== 0 ? (
            <ReduxPageLoader message={'Loading data'} />
        ) : (
            <RolesSectionDiv data-testid='review-list'>
                {this.props.category === 'group' && (
                    <GroupReviewTable
                        domain={domain}
                        groupName={collection}
                        timeZone={this.props.timeZone}
                        _csrf={this.props._csrf}
                        onUpdateSuccess={this.submitSuccess}
                        justification={this.props.justification}
                    />
                )}
                {this.props.category === 'role' && (
                    <ReviewTable
                        domain={domain}
                        role={collection}
                        roleDetails={collectionDetails}
                        members={this.props.members}
                        timeZone={this.props.timeZone}
                        _csrf={this.props._csrf}
                        onUpdateSuccess={this.submitSuccess}
                        justification={this.props.justification}
                    />
                )}
                {this.state.showSuccess ? (
                    <Alert
                        isOpen={this.state.showSuccess}
                        title={this.state.successMessage}
                        onClose={this.closeModal}
                        type='success'
                    />
                ) : null}
            </RolesSectionDiv>
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        isLoading: selectIsLoading(state),
        timeZone: selectTimeZone(state),
    };
};

export default connect(mapStateToProps)(withRouter(ReviewList));
