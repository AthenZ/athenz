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
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import styled from '@emotion/styled';
import DeleteModal from '../modal/DeleteModal';
import Menu from '../denali/Menu/Menu';
import DateUtils from '../utils/DateUtils';
import RequestUtils from '../utils/RequestUtils';
import GroupMemberList from './GroupMemberList';
import { css, keyframes } from '@emotion/react';
import { deleteMember } from '../../redux/thunks/collections';
import { connect } from 'react-redux';

const TDStyled = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
`;

const GroupTDStyled = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
    text-decoration: dashed underline;
`;

const colorTransition = keyframes`
    0% {
        background-color: rgba(21, 192, 70, 0.20);
    }
    100% {
        background-color: transparent;
    }
`;

const TrStyled = styled.tr`
    ${(props) =>
        props.isSuccess &&
        css`
            animation: ${colorTransition} 3s ease;
        `}
`;

const MenuDiv = styled.div`
    padding: 5px 10px;
    background-color: black;
    color: white;
    font-size: 12px;
`;

const LeftSpan = styled.span`
    padding-left: 20px;
`;

const StyledMenu = styled(Menu)`
    padding: 0px;
    margin-left: 0px !important;
`;

const StyledSpan = styled.span`
    &:hover {
        cursor: context-menu !important;
    }
`;

class MemberRow extends React.Component {
    constructor(props) {
        super(props);
        this.onSubmitDelete = this.onSubmitDelete.bind(this);
        this.onClickDeleteCancel = this.onClickDeleteCancel.bind(this);
        this.saveJustification = this.saveJustification.bind(this);
        this.state = {
            deleteName: this.props.details.memberName,
            showDelete: false,
        };
        this.localDate = new DateUtils();
    }

    saveJustification(val) {
        this.setState({ deleteJustification: val });
    }

    onClickDelete(name) {
        this.setState({
            showDelete: true,
            deleteName: name,
        });
    }

    onSubmitDelete() {
        let collectionName = this.props.collection;
        let name = this.state.deleteName;

        if (
            this.props.justificationRequired &&
            (this.state.deleteJustification === undefined ||
                this.state.deleteJustification.trim() === '')
        ) {
            this.setState({
                errorMessage: 'Justification is required to delete a member',
            });
            return;
        }
        this.props
            .deleteMember(
                this.props.domain,
                collectionName,
                this.props.category,
                this.state.deleteName,
                this.state.deleteJustification
                    ? this.state.deleteJustification
                    : 'deleted using Athenz UI',
                this.props.pending,
                this.props._csrf
            )
            .then(() => {
                if (this.props.pending) {
                    this.props.onUpdateSuccess(
                        `Successfully deleted pending member ${name}`,
                        true
                    );
                } else {
                    this.props.onUpdateSuccess(
                        `Successfully deleted member ${name}`,
                        true
                    );
                }
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    onClickDeleteCancel() {
        this.setState({
            showDelete: false,
            deleteName: '',
            errorMessage: null,
        });
    }

    render() {
        let rows = [];
        let left = 'left';
        let center = 'center';
        let member = this.props.details;
        let color = this.props.color;

        let clickDelete = this.onClickDelete.bind(this, this.state.deleteName);
        let submitDelete = this.onSubmitDelete.bind(this, this.props.domain);
        let clickDeleteCancel = this.onClickDeleteCancel.bind(this);
        let isSuccess =
            member.memberName +
                '-' +
                this.props.category +
                '-' +
                this.props.domain +
                '-' +
                this.props.collection ===
            this.props.newMember;
        rows.push(
            <TrStyled
                key={member.memberName}
                data-testid='member-row'
                isSuccess={isSuccess}
            >
                {member.memberName.includes(':group.') ? (
                    <GroupTDStyled color={color} align={left}>
                        <StyledMenu
                            placement='right'
                            boundary='scrollParent'
                            trigger={
                                <StyledSpan>{member.memberName}</StyledSpan>
                            }
                        >
                            <GroupMemberList
                                member={member}
                                groupName={member.memberName}
                            />
                        </StyledMenu>
                    </GroupTDStyled>
                ) : (
                    <TDStyled color={color} align={left}>
                        {member.memberName}
                    </TDStyled>
                )}
                <TDStyled color={color} align={left}>
                    {member.memberFullName}
                </TDStyled>

                <TDStyled color={color} align={left}>
                    {member.expiration
                        ? this.localDate.getLocalDate(
                              member.expiration,
                              'UTC',
                              'UTC'
                          )
                        : 'N/A'}
                </TDStyled>
                {this.props.category != 'group' && (
                    <TDStyled color={color} align={left}>
                        {member.reviewReminder
                            ? this.localDate.getLocalDate(
                                  member.reviewReminder,
                                  'UTC',
                                  'UTC'
                              )
                            : 'N/A'}
                    </TDStyled>
                )}
                <TDStyled color={color} align={center}>
                    <Menu
                        placement='bottom-start'
                        trigger={
                            <span>
                                <Icon
                                    icon={'trash'}
                                    onClick={clickDelete}
                                    color={colors.icons}
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </span>
                        }
                    >
                        <MenuDiv>Delete Member</MenuDiv>
                    </Menu>
                </TDStyled>
            </TrStyled>
        );

        if (this.state.showDelete) {
            rows.push(
                <DeleteModal
                    name={this.props.details.memberName}
                    isOpen={this.state.showDelete}
                    cancel={clickDeleteCancel}
                    submit={submitDelete}
                    key={this.props.details.memberName + '-delete'}
                    showJustification={this.props.justificationRequired}
                    message={
                        'Are you sure you want to permanently delete the Member '
                    }
                    onJustification={this.saveJustification}
                    errorMessage={this.state.errorMessage}
                />
            );
        }

        return rows;
    }
}

const mapDispatchToProps = (dispatch) => ({
    deleteMember: (
        domainName,
        collectionName,
        category,
        memberName,
        auditRef,
        pending,
        _csrf
    ) =>
        dispatch(
            deleteMember(
                domainName,
                collectionName,
                category,
                memberName,
                auditRef,
                pending,
                _csrf
            )
        ),
});

export default connect(null, mapDispatchToProps)(MemberRow);
