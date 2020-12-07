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
import { colors } from '../denali/styles/colors';
import styled from '@emotion/styled';
// there is an issue with next-link and next-css if the css is not present then it doesnt load so adding this
import 'flatpickr/dist/themes/light.css';
import CheckBox from '../denali/CheckBox';
import TextArea from '../denali/TextArea';
import FlatPicker from '../flatpicker/FlatPicker';
import Icon from '../denali/icons/Icon';
import DateUtils from '../utils/DateUtils';
import NameUtils from '../utils/NameUtils';

const TableTd = styled.td`
    text-align: left;
    vertical-align: middle;
    word-break: break-all;
    padding: 5px 0px 5px 15px;
`;

const TableTdText = styled.td`
    text-align: left;
    vertical-align: middle;
    padding: 5px 0px 5px 15px;
`;

const ErrorDiv = styled.div`
    color: #ea0000;
`;

const TableTdDomain = styled.td`
    text-align: left;
    vertical-align: middle;
    word-break: break-all;
    padding: 5px 0px 5px 0px;
`;

const FlatPickrInputDiv = styled.div`
    & > div input {
        position: relative;
        font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
        background-color: ${(props) =>
            props.disabled ? colors.grey500 : 'rgba(53, 112, 244, 0.05)'};
        box-shadow: none;
        color: rgb(48, 48, 48);
        height: 16px;
        min-width: 50px;
        text-align: left;
        border-width: 2px;
        border-style: solid;
        border-color: transparent;
        border-image: initial;
        border-radius: 2px;
        flex: 1 0 auto;
        margin: 0px;
        margin-top: 5px;
        outline: none;
        padding: 0.6em 12px;
        transition: background-color 0.2s ease-in-out 0s,
            color 0.2s ease-in-out 0s, border 0.2s ease-in-out 0s;
        width: 72%;
    }
`;

const StyledTextArea = styled(TextArea)`
    & > textarea {
        resize: vertical;
    }
`;

const ApproveTd = styled.td`
    vertical-align: middle;
    word-break: break-all;
    padding: 5px 0px 5px 15px;
    text-align: center;
`;

const RejectTd = styled.td`
    vertical-align: middle;
    word-break: break-all;
    padding: 5px 0px 5px 15px;
    text-align: center;
    border-right: none;
`;

const TableRow = styled.tr`
    background-color: ${(props) => props.color};
`;

export default class PendingApprovalTableRow extends React.Component {
    constructor(props) {
        super(props);
        this.dateUtils = new DateUtils();
    }

    render() {
        const key =
            this.props.domainName + this.props.memberName + this.props.roleName;
        const fpkey = NameUtils.getFlatPickrKey(key);
        let approveColor = this.props.checked
            ? colors.grey500
            : colors.green600;
        let rejectColor = this.props.checked
            ? colors.grey500
            : colors.statusDanger;
        let approveOnClick = this.props.checked
            ? () => {}
            : this.props.pendingDecision.bind(this, key, true);
        let rejectOnClick = this.props.checked
            ? () => {}
            : this.props.pendingDecision.bind(this, key, false);
        return (
            <TableRow
                color={this.props.color}
                data-testid='pending-approval-table-row'
                key={key}
            >
                <TableTd>
                    <CheckBox
                        checked={this.props.checked}
                        name='checkbox-row'
                        id={
                            this.props.domainName +
                            this.props.memberName +
                            this.props.roleName
                        }
                        onChange={() => {
                            this.props.checkedClick(key);
                        }}
                    />
                </TableTd>
                <TableTdDomain>{this.props.domainName}</TableTdDomain>
                <TableTd>{this.props.roleName}</TableTd>
                <TableTdText>
                    <p>{this.props.memberNameFull}</p>
                    <p>
                        {'('}
                        {this.props.memberName}
                        {')'}
                    </p>
                </TableTdText>
                <TableTdText colSpan={2}>{this.props.userComment}</TableTdText>
                <TableTdText>
                    <p>{this.props.requestPrincipalFull}</p>
                    <p>
                        {'('}
                        {this.props.requestPrincipal}
                        {')'}
                    </p>
                </TableTdText>
                <TableTd>
                    {this.dateUtils.getLocalDate(
                        this.props.requestTime,
                        'UTC',
                        'UTC'
                    )}
                </TableTd>
                <TableTd>
                    <StyledTextArea
                        id={key}
                        disabled={this.props.checked}
                        placeholder='Justification'
                        rows='4'
                        width='100%'
                        onChange={(event) => {
                            this.props.auditRefChange(key, event);
                        }}
                    />
                    {this.props.auditRefMissing ? (
                        <ErrorDiv>Justification is Required</ErrorDiv>
                    ) : null}
                </TableTd>
                <TableTd>
                    <FlatPickrInputDiv disabled={this.props.checked}>
                        <FlatPicker
                            id={fpkey}
                            onChange={(date) => {
                                this.props.dateChange(key, date);
                            }}
                            disabled={this.props.checked}
                            clear={this.props.clear}
                            value={this.props.requestedExpiry}
                            nomargin={true}
                        />
                    </FlatPickrInputDiv>
                </TableTd>
                <ApproveTd>
                    <Icon
                        disabled={this.props.checked}
                        icon={'check-circle'}
                        onClick={approveOnClick}
                        color={approveColor}
                        isLink
                        size={'1.25em'}
                        verticalAlign={'text-bottom'}
                    />
                </ApproveTd>
                <RejectTd>
                    <Icon
                        disabled={this.props.checked}
                        icon={'decline'}
                        onClick={rejectOnClick}
                        color={rejectColor}
                        isLink
                        size={'1.25em'}
                        verticalAlign={'text-bottom'}
                    />
                </RejectTd>
            </TableRow>
        );
    }
}
