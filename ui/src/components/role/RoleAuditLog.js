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
import DateUtils from '../utils/DateUtils';
import Menu from '../denali/Menu/Menu';

const AuditLogSectionDiv = styled.div`
    margin: 20px;
`;

const AuditLogTable = styled.table`
    width: 100%;
    border-spacing: 0;
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

const TDStyled = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
    border-bottom: 1px solid #d5d5d5;
`;

const MenuDiv = styled.div`
    padding: 5px 10px;
    background-color: black;
    color: white;
    font-size: 12px;
`;

export default class RoleAuditLog extends React.Component {
    constructor(props) {
        super(props);
        this.state = {};
        this.localDate = new DateUtils();
    }

    render() {
        const left = 'left';
        let { color } = this.props;

        const rows = this.props.auditLogRows
            .sort((a, b) => {
                return b.created.localeCompare(a.created);
            })
            .map((item, i) => {
                return (
                    <tr key={'audit-log-' + i}>
                        <TDStyled color={color} align={left}>
                            {item.action}
                        </TDStyled>
                        <TDStyled color={color} align={left}>
                            <Menu
                                placement='bottom-start'
                                trigger={
                                    <span>
                                        {item.adminFullName
                                            ? item.adminFullName
                                            : item.admin}
                                    </span>
                                }
                            >
                                <MenuDiv>{item.admin}</MenuDiv>
                            </Menu>
                        </TDStyled>
                        <TDStyled color={color} align={left}>
                            {this.localDate.getLocalDate(
                                item.created,
                                'UTC',
                                'UTC'
                            )}
                        </TDStyled>
                        <TDStyled color={color} align={left}>
                            <Menu
                                placement='bottom-start'
                                trigger={
                                    <span>
                                        {item.memberFullName
                                            ? item.memberFullName
                                            : item.member}
                                    </span>
                                }
                            >
                                <MenuDiv>{item.member}</MenuDiv>
                            </Menu>
                        </TDStyled>
                        <TDStyled color={color} align={left}>
                            {item.auditRef && item.auditRef !== 'undefined'
                                ? item.auditRef
                                : ''}
                        </TDStyled>
                    </tr>
                );
            });

        return (
            <AuditLogSectionDiv data-testid='audit-log-list'>
                <AuditLogTable>
                    <thead>
                        <tr>
                            <TableHeadStyled align={left}>
                                ACTION
                            </TableHeadStyled>
                            <TableHeadStyled align={left}>
                                EXECUTED BY
                            </TableHeadStyled>
                            <TableHeadStyled align={left}>DATE</TableHeadStyled>
                            <TableHeadStyled align={left}>
                                MEMBER
                            </TableHeadStyled>
                            <TableHeadStyled align={left}>
                                AUDIT REFERENCE
                            </TableHeadStyled>
                        </tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </AuditLogTable>
            </AuditLogSectionDiv>
        );
    }
}
