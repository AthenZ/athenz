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
import { selectGroupMembers } from '../../redux/selectors/group';
import { reviewGroup } from '../../redux/thunks/groups';
import { connect } from 'react-redux';
import produce from 'immer';

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
    font-size: 0.8rem;
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

class GroupReviewTable extends React.Component {
    constructor(props) {
        super(props);
        this.submitReview = this.submitReview.bind(this);
        this.onUpdate = this.onUpdate.bind(this);
        let members = props.members && props.members.map((m) => m.memberName);
        this.state = {
            submittedReview: false,
            extendedMembers: new Set(members),
            deletedMembers: new Set(),
        };
    }
    loadGroup() {
        let members =
            this.props.members && this.props.members.map((m) => m.memberName);
        this.setState({
            extendedMembers: new Set(members),
            deletedMembers: new Set(),
            submittedReview: false,
        });
    }

    inputChanged(key, evt) {
        this.setState({ [key]: evt.target.value });
    }

    submitReview() {
        if (this.props.members && this.props.members.length > 0) {
            if (
                this.state.justification === undefined ||
                this.state.justification.trim() === ''
            ) {
                this.setState({
                    errorMessage:
                        'Justification is required to submit the review.',
                });
                return;
            }

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
                        `Successfully submitted the review for group ${this.props.groupName}`
                    );
                    this.loadGroup();
                })
                .catch((err) => {
                    this.setState({
                        errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                    });
                });
        }
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
                      .map((item, i) => {
                          let color = 'white';
                          return (
                              <ReviewRow
                                  category={'group'}
                                  key={'group-review-' + i}
                                  idx={'group-review-' + i}
                                  details={item}
                                  collection={this.props.groupName}
                                  color={color}
                                  onUpdate={this.onUpdate}
                                  submittedReview={this.state.submittedReview}
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

        if (!this.props.members || this.props.members.length === 0) {
            return (
                <ReviewMembersContainerDiv>
                    There is no members to review for group: {this.props.groupName}.
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
                                    <SubmitDiv>
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
            </ReviewMembersContainerDiv>
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        members: selectGroupMembers(state, props.domain, props.groupName),
    };
};

const mapDispatchToProps = (dispatch) => ({
    reviewGroup: (groupName, group, justification, _csrf) =>
        dispatch(reviewGroup(groupName, group, justification, _csrf)),
});

export default connect(mapStateToProps, mapDispatchToProps)(GroupReviewTable);
