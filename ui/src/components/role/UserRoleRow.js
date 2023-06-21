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
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import DateUtils from '../utils/DateUtils';
import { css, keyframes } from '@emotion/react';
import nameUtils from '../utils/NameUtils';

const StyleTable = styled.div`
    width: 100%;
    border-spacing: 0 15px;
    display: table;
    border-collapse: separate;
    border-color: grey;
`;

const TableHeadStyled = styled.div`
    border-bottom: 2px solid rgb(213, 213, 213);
    color: rgb(154, 154, 154);
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0px 5px 15px;
    word-break: break-all;
    display: flex;
`;

const LeftMarginSpan = styled.span`
    margin-right: 10px;
    vertical-align: bottom;
`;

const TDStyledMember = styled.div`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
    width: 70%;
`;

const TDStyledIcon = styled.div`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
    width: 15%;
`;

const TrStyled = styled.div`
    box-sizing: border-box;
    margin-top: 10px;
    box-shadow: 0 1px 4px #d9d9d9;
    border: 1px solid #fff;
    -webkit-border-image: none;
    border-image: none;
    -webkit-border-image: initial;
    border-image: initial;
    display: flex;
    ${(props) =>
        props.isSuccess === true &&
        css`
            animation: ${colorTransition} 3s ease;
        `}
`;

const colorTransition = keyframes`
        0% {
            background-color: rgba(21, 192, 70, 0.20);
        }
        100% {
            background-color: transparent;
        }
`;

const StyledTd = styled.div`
    width: 100%;
`;

const StyledTable = styled.div`
    width: 100%;
`;

const StyledUserCol = styled.div`
    text-align: ${(props) => props.align};
    width: 70%;
`;

const StyledIconCol = styled.div`
    text-align: ${(props) => props.align};
    width: 15%;
`;

const FlexDiv = styled.div`
    display: flex;
`;
const randomRange = 100000000;
export default class UserRoleRow extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            isExpand: false,
        };
        this.dateUtils = new DateUtils();
        this.expandRole = this.expandRole.bind(this);
    }

    expandRole() {
        this.setState({ isExpand: !this.state.isExpand });
    }

    expandMember(roles, memberName) {
        const { deleteRoleMember } = this.props;
        return roles.map((role) => {
            return (
                <FlexDiv key={role.roleName}>
                    <TDStyledMember align={'left'}>
                        {role.roleName}
                    </TDStyledMember>
                    <TDStyledIcon align={'center'}>
                        {role.expiration
                            ? this.dateUtils.getLocalDate(
                                  role.expiration,
                                  this.props.timeZone,
                                  this.props.timeZone
                              )
                            : null}
                    </TDStyledIcon>
                    <TDStyledIcon align={'center'}>
                        <Icon
                            icon={'trash'}
                            onClick={() =>
                                deleteRoleMember(
                                    nameUtils.getShortName(
                                        ':role.',
                                        role.roleName
                                    ),
                                    memberName
                                )
                            }
                            color={colors.icons}
                            isLink
                            size={'1.25em'}
                            verticalAlign={'text-bottom'}
                        />
                    </TDStyledIcon>
                </FlexDiv>
            );
        });
    }

    render() {
        const { newMember, memberData, onDelete } = this.props;
        return (
            <TrStyled
                key={memberData.memberName}
                isSuccess={newMember}
                key={
                    memberData.memberName +
                    (Math.random() * randomRange).toString()
                }
            >
                <StyledTd>
                    <StyledTable>
                        <FlexDiv>
                            <TDStyledMember align={'left'}>
                                <LeftMarginSpan>
                                    <Icon
                                        icon={'arrowhead-down-circle'}
                                        onClick={this.expandRole}
                                        color={colors.icons}
                                        isLink
                                        size={'1.5em'}
                                        verticalAlign={'text-bottom'}
                                    />
                                </LeftMarginSpan>
                                {memberData.memberName +
                                    (memberData.memberFullName !== undefined &&
                                    memberData.memberFullName !== null
                                        ? ' (' + memberData.memberFullName + ')'
                                        : '') +
                                    ' (' +
                                    memberData.memberRoles.length +
                                    ')'}
                            </TDStyledMember>
                            <TDStyledIcon align={'center'} />
                            <TDStyledIcon align={'center'}>
                                <Icon
                                    icon={'trash'}
                                    onClick={() =>
                                        onDelete(memberData.memberName)
                                    }
                                    color={colors.icons}
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </TDStyledIcon>
                        </FlexDiv>
                        {this.state.isExpand
                            ? this.expandMember(
                                  memberData.memberRoles,
                                  memberData.memberName
                              )
                            : null}
                    </StyledTable>
                </StyledTd>
            </TrStyled>
        );
    }
}
