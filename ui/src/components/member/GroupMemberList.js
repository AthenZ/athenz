/*
 * Copyright 2020 Verizon Media
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
import DateUtils from '../utils/DateUtils';
import { withRouter } from 'next/router';

const StyleTable = styled.table`
    width: 100%;
    text-align: center;
    border-spacing: 0;
    display: table;
    border-collapse: separate;
    border-color: black;
    box-sizing: border-box;
    margin-top: 5px;
    box-shadow: 0 1px 4px #d9d9d9;
    border: 5px solid #fff;
    -webkit-border-image: none;
    border-image: none;
    -webkit-border-image: initial;
    border-image: initial;
    height: 50px;
`;

const StyleDiv = styled.table`
    width: 100%;
    border-spacing: 0;
    display: table;
    border-collapse: separate;
    border-color: grey;
    box-sizing: border-box;
    margin-top: 5px;
    box-shadow: 0 1px 4px #d9d9d9;
    border: 1px solid #fff;
    -webkit-border-image: none;
    border-image: none;
    -webkit-border-image: initial;
    border-image: initial;
    height: 50px;
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

const TableHeadStyledRoleName = styled.th`
    text-align: ${(props) => props.align};
    border-bottom: 2px solid #d5d5d5;
    color: #9a9a9a;
    font-weight: 600;
    font-size: 0.8rem;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 35px;
    word-break: break-all;
`;

const TableCaptionStyled = styled.caption`
    height: 25px;
    margin-left: 10px;
    margin-top: 10px;
    text-align: left;
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
    display: block;
`;

const LeftMarginSpan = styled.span`
    margin-right: 10px;
    verticalAlign：bottom；
`;

const StyledTr = styled.tr`
    &:nth-child(even) {
        background-color: #3570f40d;
    }
`;

const StyledTh = styled.th`
    padding: 6px;
    border: 1px solid #dddddd;
`;

const StyledTd = styled.td`
    border: 1px solid #dddddd;
    padding: 5px;
`;

class GroupMemberList extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.viewGroup = this.viewGroup.bind(this);
        this.localDate = new DateUtils();
    }

    viewGroup(e) {
        e.stopPropagation();
        let dom = this.props.groupName.split(':group.')[0];
        let grp = this.props.groupName.split(':group.')[1];
        this.props.router.push(
            `/domain/${dom}/group/${grp}/members`,
            `/domain/${dom}/group/${grp}/members`,
            { getInitialProps: true }
        );
    }

    render() {
        const { member } = this.props;
        let rows;
        if (member.groupMembers) {
            rows = member.groupMembers.map((item, i) => {
                return (
                    <StyledTr>
                        <StyledTd>{item.memberName}</StyledTd>
                        <StyledTd>
                            {item.expiration
                                ? this.localDate.getLocalDate(
                                      item.expiration,
                                      'UTC',
                                      'UTC'
                                  )
                                : 'N/A'}
                        </StyledTd>
                    </StyledTr>
                );
            });
        } else {
            rows = (
                <StyledTr>
                    <StyledTd colSpan={2}>{'No members in group.'}</StyledTd>
                </StyledTr>
            );
        }

        return (
            <StyleTable>
                {member.groupMembers ? (
                    <StyledTr>
                        <StyledTh> Member </StyledTh>
                        <StyledTh> Expiry </StyledTh>
                    </StyledTr>
                ) : (
                    ''
                )}

                {rows}
                <StyledTr>
                    <StyledTd colSpan={2}>
                        <Button secondary onClick={this.viewGroup}>
                            View Members
                        </Button>
                    </StyledTd>
                </StyledTr>
            </StyleTable>
        );
    }
}
export default withRouter(GroupMemberList);
