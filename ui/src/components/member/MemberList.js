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
import Button from '../denali/Button';
import Alert from '../denali/Alert';
import { MODAL_TIME_OUT } from '../constants/constants';
import AddMember from './AddMember';
import MemberTable from './MemberTable';
import { selectIsLoading } from '../../redux/selectors/loading';
import { selectTimeZone } from '../../redux/selectors/domains';
import { connect } from 'react-redux';
import { ReduxPageLoader } from '../denali/ReduxPageLoader';
import { arrayEquals } from '../utils/ArrayUtils';

const MembersSectionDiv = styled.div`
    margin: 20px;
`;

const AddContainerDiv = styled.div`
    padding-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-flow: row nowrap;
    float: right;
`;

class MemberList extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            showuser: false,
            showAddMember: false,
            members: props.members || [],
            errorMessage: null,
        };
        this.toggleAddMember = this.toggleAddMember.bind(this);
        this.closeModal = this.closeModal.bind(this);
        this.reloadMembers = this.reloadMembers.bind(this);
    }

    toggleAddMember() {
        this.setState({
            showAddMember: !this.state.showAddMember,
        });
    }

    componentDidUpdate = (prevProps) => {
        if (
            prevProps.collection !== this.props.collection ||
            prevProps.domain !== this.props.domain ||
            !arrayEquals(prevProps.members, this.props.members)
        ) {
            this.setState({
                members: this.props.members,
                showuser: false,
            });
        }
    };

    reloadMembers(successMessage, showSuccess = true) {
        this.setState({
            showAddMember: false,
            showSuccess,
            successMessage: successMessage,
            errorMessage: null,
        });
        setTimeout(
            () =>
                this.setState({
                    showSuccess: false,
                    successMessage: '',
                }),
            MODAL_TIME_OUT
        );
    }

    closeModal() {
        this.setState({ showSuccess: null });
    }

    render() {
        const { domain, collection, collectionDetails } = this.props;
        let approvedMembers = [];
        let pendingMembers = [];
        let addMemberButton = '';
        let justificationReq =
            this.props.isDomainAuditEnabled ||
            collectionDetails.reviewEnabled ||
            collectionDetails.selfServe;
        let addMember = this.state.showAddMember ? (
            <AddMember
                category={this.props.category}
                domainName={this.props.domain}
                collection={this.props.collection}
                onSubmit={this.reloadMembers}
                onCancel={this.toggleAddMember}
                _csrf={this.props._csrf}
                showAddMember={this.state.showAddMember}
                justificationRequired={justificationReq}
            />
        ) : (
            ''
        );
        if (collectionDetails.trust) {
            approvedMembers = this.props.members;
        } else {
            approvedMembers = this.props.members
                ? this.props.members.filter((item) => item.approved)
                : [];
            pendingMembers = this.props.members
                ? this.props.members.filter((item) => !item.approved)
                : [];
        }
        addMemberButton = (
            <AddContainerDiv>
                <div>
                    <Button secondary onClick={this.toggleAddMember}>
                        Add Member
                    </Button>
                    {addMember}
                </div>
            </AddContainerDiv>
        );

        let showPending = pendingMembers.length > 0;
        let newMember = this.state.successMessage;
        return this.props.isLoading.length !== 0 ? (
            <ReduxPageLoader message={'Loading members'} />
        ) : (
            <MembersSectionDiv data-testid='member-list'>
                {addMemberButton}
                <MemberTable
                    category={this.props.category}
                    domain={domain}
                    collection={collection}
                    members={approvedMembers}
                    caption='Approved'
                    timeZone={this.props.timeZone}
                    _csrf={this.props._csrf}
                    onSubmit={this.reloadMembers}
                    justificationRequired={justificationReq}
                    newMember={newMember}
                />
                <br />
                {showPending ? (
                    <MemberTable
                        category={this.props.category}
                        domain={domain}
                        collection={collection}
                        members={pendingMembers}
                        pending={true}
                        caption='Pending'
                        timeZone={this.props.timeZone}
                        _csrf={this.props._csrf}
                        onSubmit={this.reloadMembers}
                        justificationRequired={justificationReq}
                        newMember={newMember}
                    />
                ) : null}
                {this.state.showSuccess ? (
                    <Alert
                        isOpen={this.state.showSuccess}
                        title={this.state.successMessage}
                        onClose={this.closeModal}
                        type='success'
                    />
                ) : null}
            </MembersSectionDiv>
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

export default connect(mapStateToProps)(MemberList);
