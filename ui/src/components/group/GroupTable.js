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
import GroupRow from './GroupRow';

const StyleTable = styled.table`
    width: 100%;
    border-spacing: 0 15px;
    display: table;
    border-collapse: separate;
    border-color: grey;
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

const TableHeadStyledGroupName = styled.th`
    text-align: ${(props) => props.align};
    border-bottom: 2px solid #d5d5d5;
    color: #9a9a9a;
    font-weight: 600;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 35px;
    word-break: break-all;
`;

// we dont connect it to the store because we want to use the groups from the props after filter by search
export default class GroupTable extends React.Component {
    constructor(props) {
        super(props);
    }

    render() {
        const { domain, groups } = this.props;
        let rows = [];
        if (groups && groups.length > 0) {
            rows = groups
                .sort((a, b) => {
                    return a.name.localeCompare(b.name);
                })
                .map((item, i) => {
                    let color = '';
                    return (
                        <GroupRow
                            details={item}
                            idx={i}
                            domain={domain}
                            color={color}
                            key={item.name}
                            onUpdateSuccess={this.props.onSubmit}
                            timeZone={this.props.timeZone}
                            _csrf={this.props._csrf}
                            justificationRequired={
                                this.props.justificationRequired
                            }
                            newGroup={this.props.newGroup}
                        />
                    );
                });
        }

        return (
            <StyleTable key='group-table' data-testid='grouptable'>
                <colgroup>
                    <col style={{ width: 26 + '%' }} />
                    <col style={{ width: 13 + '%' }} />
                    <col style={{ width: 13 + '%' }} />
                    <col style={{ width: 8 + '%' }} />
                    <col style={{ width: 8 + '%' }} />
                    <col style={{ width: 8 + '%' }} />
                    <col style={{ width: 8 + '%' }} />
                    <col style={{ width: 8 + '%' }} />
                    <col style={{ width: 8 + '%' }} />
                </colgroup>
                <thead>
                    <tr>
                        <TableHeadStyledGroupName align={'left'}>
                            Group
                        </TableHeadStyledGroupName>
                        <TableHeadStyled>Modified Date</TableHeadStyled>
                        <TableHeadStyled>Reviewed Date</TableHeadStyled>
                        <TableHeadStyled>Members</TableHeadStyled>
                        <TableHeadStyled>Roles</TableHeadStyled>
                        <TableHeadStyled>Tags</TableHeadStyled>
                        <TableHeadStyled>Settings</TableHeadStyled>
                        <TableHeadStyled>History</TableHeadStyled>
                        <TableHeadStyled>Delete</TableHeadStyled>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </StyleTable>
        );
    }
}
