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
import ReviewRow from '../review/ReviewRow';
import Button from '../denali/Button';
import Color from '../denali/Color';
import Input from '../denali/Input';
import RequestUtils from '../utils/RequestUtils';
import { selectReviewGroupMembers } from '../../redux/selectors/groups';
import { reviewGroup } from '../../redux/thunks/groups';
import { connect } from 'react-redux';
import produce from 'immer';
import CollectionUtils from 'lodash';
import DeleteModal from '../modal/DeleteModal';

const TitleDiv = styled.div`
    font-size: 16px;
    font-weight: 600;
`;

const ReviewMembersContainerDiv = styled.div`
    margin: 0;
`;

const ReviewMembersSectionDiv = styled.div`
    margin: 20px;
`;

const ReviewMembersTable = styled.table`
    width: 100%;
    border-spacing: 0 15px;
    display: table;
    border-collapse: separate;
    border-color: grey;
    table-layout: fixed;
`;

const TableHeadStyled = styled.th`
    text-align: ${(props) => props.align};
    border-bottom: 2px solid #d5d5d5;
    color: #9a9a9a;
    font-weight: 600;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 15px;
    word-break: break-all;
`;

const SubmitDiv = styled.div`
    margin-top: 10px;
`;

const SubmitTextSpan = styled.span`
    color: #9a9a9a;
`;

const ContentDiv = styled.div`
    flex: 1 1;
    margin-right: 10px;
`;

const StyledJustification = styled(Input)`
    width: 300px;
    margin-top: 5px;
`;

const MessageP = styled.p`
    width: 500px;
`;

class GroupReviewTable extends React.Component {
    constructor(props) {
        super(props);
        this.submitReview = this.submitReview.bind(this);
        this.updateReviewGroup = this.updateReviewGroup.bind(this);
        this.onClickDeleteCancel = this.onClickDeleteCancel.bind(this);
        this.onUpdate = this.onUpdate.bind(this);
        let members = props.members && props.members.map((m) => m.memberName);
        this.state = {
            submittedReview: false,
            showDeleteConfirmation: false,
            extendedMembers: new Set(members),
            deletedMembers: new Set(),
            justification: props.justification || '',
        };
    }

    componentDidUpdate(prevProps) {
        if (prevProps.justification !== this.props.justification) {
            this.setState({
                justification: this.props.justification,
            });
        }
    }

    inputChanged(key, evt) {
        this.setState({ [key]: evt.target.value });
    }

    onClickDeleteCancel() {
        this.setState({ showDeleteConfirmation: false });
    }

    submitReview() {
        if (
            this.state.justification === undefined ||
            this.state.justification.trim() === ''
        ) {
            this.setState({
                errorMessage: 'Justification is required to submit the review.',
            });
            return;
        }

        // show prompt for user to ask for confirmation once the user asked to delete member/s

        if (this.state.deletedMembers.size > 0) {
            this.setState({ showDeleteConfirmation: true });
        } else {
            this.updateReviewGroup();
        }
    }

    updateReviewGroup() {
        //construct role object from state
        let group = {
            name: this.props.groupName,
        };
        group.groupMembers = produce(this.props.members, (draft) => {
            draft.forEach((member) => {
                if (this.state.deletedMembers.has(member.memberName)) {
                    member.active = false;
                }
                member.expiration = null;
                delete member.memberFullName;
            });
        });
        group.groupMembers = group.groupMembers.filter((m) => {
            if (
                this.state.deletedMembers.has(m.memberName) ||
                this.state.extendedMembers.has(m.memberName)
            ) {
                return m;
            }
        });
        this.props
            .reviewGroup(
                this.props.groupName,
                group,
                this.state.justification,
                this.props._csrf
            )
            .then(() => {
                this.setState({
                    submittedReview: true,
                    errorMessage: null,
                    justification: '',
                });
                this.props.onUpdateSuccess(
                    `Successfully submitted the review for group ${this.props.groupName}.`
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    onUpdate(key, value) {
        switch (key) {
            case 'delete':
                this.state.deletedMembers.add(value);
                this.state.extendedMembers.delete(value);
                break;
            case 'extend':
                this.state.extendedMembers.add(value);
                this.state.deletedMembers.delete(value);
                break;
            case 'no-action':
                this.state.deletedMembers.delete(value);
                this.state.extendedMembers.delete(value);
                break;
        }
    }

    render() {
        const left = 'left';
        let center = 'center';
        const rows =
            this.props.members && this.props.members.length > 0
                ? this.props.members
                      .sort((a, b) => {
                          return a.memberName.localeCompare(b.memberName);
                      })
                      .map((item) => {
                          let color = 'white';
                          return (
                              <ReviewRow
                                  category={'group'}
                                  key={
                                      'group-review-' +
                                      this.props.groupName +
                                      item.memberName
                                  }
                                  idx={
                                      'group-review-' +
                                      this.props.groupName +
                                      item.memberName
                                  }
                                  details={item}
                                  collection={this.props.groupName}
                                  color={color}
                                  onUpdate={this.onUpdate}
                                  submittedReview={this.state.submittedReview}
                                  timeZone={this.props.timeZone}
                              />
                          );
                      })
                : [];
        if (this.state.showTrustError) {
            return (
                <ReviewMembersContainerDiv>
                    <ContentDiv>
                        {this.state.errorMessage && (
                            <Color name={'red600'}>
                                {this.state.errorMessage}
                            </Color>
                        )}
                    </ContentDiv>
                </ReviewMembersContainerDiv>
            );
        }

        return (
            <ReviewMembersContainerDiv>
                <TitleDiv>REVIEW GROUP MEMBERS</TitleDiv>
                <ReviewMembersSectionDiv data-testid='review-table'>
                    <ReviewMembersTable>
                        <thead>
                            <tr>
                                <TableHeadStyled align={left}>
                                    MEMBER
                                </TableHeadStyled>
                                <TableHeadStyled align={left}>
                                    MEMBER NAME
                                </TableHeadStyled>
                                <TableHeadStyled align={left} colSpan={2}>
                                    EXPIRATION DATE
                                </TableHeadStyled>
                                <TableHeadStyled align={center}>
                                    EXTEND
                                </TableHeadStyled>
                                <TableHeadStyled align={center}>
                                    NO ACTION
                                </TableHeadStyled>
                                <TableHeadStyled align={center}>
                                    DELETE
                                </TableHeadStyled>
                            </tr>
                        </thead>
                        <tbody>
                            {rows}
                            {rows.length > 0 ? (
                                ''
                            ) : (
                                <MessageP key='no-members'>
                                    There are no members to review for group:{' '}
                                    {this.props.groupName}.
                                </MessageP>
                            )}
                            <tr key='submit-review'>
                                <td colSpan={2}>
                                    <StyledJustification
                                        id='justification'
                                        name='justification'
                                        value={
                                            this.state.justification
                                                ? this.state.justification
                                                : ''
                                        }
                                        onChange={this.inputChanged.bind(
                                            this,
                                            'justification'
                                        )}
                                        autoComplete={'off'}
                                        placeholder='Enter justification here'
                                    />
                                </td>
                                <td colSpan={1}>
                                    <SubmitDiv
                                        id={
                                            'submit-button-' +
                                            this.props.groupName
                                        }
                                    >
                                        <Button
                                            secondary={true}
                                            onClick={this.submitReview}
                                        >
                                            Submit Review
                                        </Button>
                                    </SubmitDiv>
                                </td>
                                <td colSpan={3}></td>
                            </tr>
                            <tr key='error-message'>
                                <td colSpan={6}>
                                    {this.state.errorMessage && (
                                        <Color name={'red600'}>
                                            {this.state.errorMessage}
                                        </Color>
                                    )}
                                </td>
                            </tr>
                        </tbody>
                    </ReviewMembersTable>
                </ReviewMembersSectionDiv>
                {this.state.showDeleteConfirmation && (
                    <DeleteModal
                        name={this.props.groupName}
                        isOpen={this.state.showDeleteConfirmation}
                        cancel={this.onClickDeleteCancel}
                        submit={this.updateReviewGroup}
                        key={this.props.groupName + '-delete'}
                        message={
                            'Are you sure you want to permanently delete member/s from group '
                        }
                    />
                )}
            </ReviewMembersContainerDiv>
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        members: selectReviewGroupMembers(state, props.domain, props.groupName),
    };
};

const mapDispatchToProps = (dispatch) => ({
    reviewGroup: (groupName, group, justification, _csrf) =>
        dispatch(reviewGroup(groupName, group, justification, _csrf)),
});

export default connect(mapStateToProps, mapDispatchToProps)(GroupReviewTable);
