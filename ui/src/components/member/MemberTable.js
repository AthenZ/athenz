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
import { colors } from '../denali/styles';
import MemberRow from './MemberRow';
import Icon from '../denali/icons/Icon';

const StyleTable = styled.table`
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

export default class MemberTable extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;

        this.state = {
            expanded: true,
        };
    }

    expandMembers() {
        this.setState({
            expanded: !this.state.expanded,
        });
    }

    render() {
        const center = 'center';
        const left = 'left';
        const { domain, role, caption } = this.props;
        const arrowup = 'arrowhead-up-circle-solid';
        const arrowdown = 'arrowhead-down-circle';
        let expandMembers = this.expandMembers.bind(this);
        let rows = [];
        let length = this.props.members ? this.props.members.length : 0;

        if (this.props.members && this.props.members.length > 0) {
            rows = this.props.members
                .sort((a, b) => {
                    return a.memberName.localeCompare(b.memberName);
                })
                .map((item, i) => {
                    let color = '';
                    if (i % 2 === 0) {
                        color = colors.row;
                    }
                    return (
                        <MemberRow
                            domain={domain}
                            role={role}
                            details={item}
                            idx={i}
                            color={color}
                            api={this.api}
                            key={item.memberName}
                            onUpdateSuccess={this.props.onSubmit}
                            _csrf={this.props._csrf}
                            justificationRequired={
                                this.props.justificationRequired
                            }
                            userProfileLink={this.props.userProfileLink}
                        />
                    );
                });
        }

        if (!this.state.expanded) {
            return (
                <StyleTable data-testid='member-table'>
                    <thead>
                        <TableCaptionStyled>
                            <LeftMarginSpan>
                                <Icon
                                    icon={
                                        this.state.expanded
                                            ? arrowup
                                            : arrowdown
                                    }
                                    onClick={expandMembers}
                                    color={colors.icons}
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </LeftMarginSpan>
                            {`${caption} (${length})`}
                        </TableCaptionStyled>
                    </thead>
                </StyleTable>
            );
        }

        return (
            <StyleTable data-testid='member-table'>
                <thead>
                    <TableCaptionStyled>
                        <LeftMarginSpan>
                            <Icon
                                icon={this.state.expanded ? arrowup : arrowdown}
                                onClick={expandMembers}
                                color={colors.icons}
                                isLink
                                size={'1.25em'}
                                verticalAlign={'text-bottom'}
                            />
                        </LeftMarginSpan>
                        {`${caption} (${length})`}
                    </TableCaptionStyled>
                    <tr>
                        <TableHeadStyledRoleName align={left}>
                            User Name
                        </TableHeadStyledRoleName>
                        <TableHeadStyled align={left}>
                            Name of User
                        </TableHeadStyled>
                        <TableHeadStyled align={left}>
                            Expiration Date
                        </TableHeadStyled>
                        <TableHeadStyled align={center}>Delete</TableHeadStyled>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </StyleTable>
        );
    }
}
