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
    width: ${(props) => `${props.width}%`};
    border-bottom: 2px solid #d5d5d5;
    color: #9a9a9a;
    font-weight: 600;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 15px;
    word-break: break-all;
`;

const TableHeadStyledRoleName = styled.th`
    text-align: ${(props) => props.align};
    width: ${(props) => `${props.width}%`};
    border-bottom: 2px solid #d5d5d5;
    color: #9a9a9a;
    font-weight: 600;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 35px;
    word-break: break-all;
`;

const TableThStyled = styled.th`
    height: 25px;
    margin-left: 10px;
    margin-top: 10px;
    text-align: left;
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    font-weight: lighter;
    word-break: break-all;
    display: block;
`;

const LeftMarginSpan = styled.span`
    margin-right: 10px;
    verticalalign: bottom;
`;

export default class MemberTable extends React.Component {
    constructor(props) {
        super(props);

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
        const { domain, collection, caption } = this.props;
        const arrowup = 'arrowhead-up-circle-solid';
        const arrowdown = 'arrowhead-down-circle';
        let expandMembers = this.expandMembers.bind(this);
        let rows = [];
        let length = this.props.members ? this.props.members.length : 0;
        let columnWidthPercentages = this.props.category === 'role' ? 19.5 : 26;
        let pendingStateColumnWidthPercentages = 14;
        let deleteColumnWidthPercentages = 8;
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
                            category={this.props.category}
                            domain={domain}
                            collection={collection}
                            pending={this.props.pending}
                            details={item}
                            idx={i}
                            color={color}
                            key={item.memberName}
                            onUpdateSuccess={this.props.onSubmit}
                            timeZone={this.props.timeZone}
                            _csrf={this.props._csrf}
                            justificationRequired={
                                this.props.justificationRequired
                            }
                            newMember={this.props.newMember}
                        />
                    );
                });
        }

        if (!this.state.expanded) {
            return (
                <StyleTable data-testid='member-table'>
                    <tbody>
                        <tr>
                            <TableThStyled>
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
                            </TableThStyled>
                        </tr>
                    </tbody>
                </StyleTable>
            );
        }

        return (
            <StyleTable data-testid='member-table'>
                <thead>
                    <tr>
                        <TableThStyled>
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
                        </TableThStyled>
                    </tr>
                    <tr>
                        <TableHeadStyledRoleName
                            width={columnWidthPercentages}
                            align={left}
                        >
                            User Name
                        </TableHeadStyledRoleName>
                        <TableHeadStyled
                            width={columnWidthPercentages}
                            align={left}
                        >
                            Name of User
                        </TableHeadStyled>
                        <TableHeadStyled
                            width={
                                this.props.category === 'group' &&
                                !this.props.pending
                                    ? columnWidthPercentages +
                                      pendingStateColumnWidthPercentages
                                    : columnWidthPercentages
                            }
                            align={left}
                        >
                            Expiration Date
                        </TableHeadStyled>
                        {this.props.category !== 'group' && (
                            <TableHeadStyled
                                width={
                                    this.props.pending
                                        ? columnWidthPercentages
                                        : columnWidthPercentages +
                                          pendingStateColumnWidthPercentages
                                }
                                align={left}
                            >
                                Review Reminder Date
                            </TableHeadStyled>
                        )}
                        {this.props.pending && (
                            <TableHeadStyled
                                width={pendingStateColumnWidthPercentages}
                                align={left}
                            >
                                Pending State
                            </TableHeadStyled>
                        )}
                        <TableHeadStyled
                            width={deleteColumnWidthPercentages}
                            align={center}
                        >
                            Delete
                        </TableHeadStyled>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </StyleTable>
        );
    }
}
