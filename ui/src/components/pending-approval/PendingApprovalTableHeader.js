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
import TextArea from '../denali/TextArea';
import Icon from '../denali/icons/Icon';
import FlatPicker from '../flatpicker/FlatPicker';
import CheckBox from '../denali/CheckBox';

const SelectAllRejectTableHeader = styled.th`
    border-bottom: 2px solid ${colors.grey500};
    color: ${colors.grey600};
    font-weight: 600;
    padding-bottom: 5px;
    vertical-align: middle;
    text-transform: uppercase;
    text-align: center;
    border-right: none;
    padding: 5px 0 5px 15px;
`;

const ErrorDiv = styled.div`
    color: #ea0000;
    font-weight: 300;
`;

const SelectAllRejectTableHeaderCheckBox = styled.th`
    border-bottom: 2px solid ${colors.grey500};
    color: ${colors.grey600};
    font-weight: 600;
    padding-bottom: 5px;
    vertical-align: middle;
    text-transform: uppercase;
    text-align: center;
    border-right: none;
    padding: 5px 0 5px 15px;
    width: 1%;
`;

const StyledTextArea = styled(TextArea)`
    & > textarea {
        resize: vertical;
    }
`;

const SelectAllApproveTableHeader = styled.th`
    border-bottom: 2px solid ${colors.grey500};
    color: ${colors.grey600};
    font-weight: 600;
    padding-bottom: 5px;
    vertical-align: middle;
    text-transform: uppercase;
    text-align: center;
    padding: 5px 0 5px 15px;
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
        width: 75%;
    }
`;

const TableHeader = styled.th`
    border-bottom: 2px solid ${colors.grey500};
    color: ${colors.grey600};
    font-weight: 600;
    font-size: 0.7rem;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 15px;
    text-align: left;
`;

const TableHeaderSelectAll = styled.th`
    border-bottom: 2px solid ${colors.grey500};
    color: ${colors.grey600};
    font-weight: 600;
    font-size: 0.7rem;
    padding-bottom: 5px;
    vertical-align: middle;
    text-transform: uppercase;
    padding: 5px 0 5px 0px;
    text-align: left;
`;

const SelectAllBoxTableHeader = styled.th`
    border-bottom: 2px solid ${colors.grey500};
    font-weight: 600;
    font-size: 0.7rem;
    padding-bottom: 5px;
    vertical-align: bottom;
    padding: 5px 0 5px 15px;
    text-align: left;
`;

export default class PendingApprovalTableHeader extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.state = {
            checked: this.props.checked,
        };
    }

    render() {
        let checked = this.props.checked;
        let disabled = false;
        if (this.props.checkedList.length === 0) {
            disabled = true;
        }
        let approveColor = disabled ? colors.grey500 : colors.green600;
        let rejectColor = disabled ? colors.grey500 : colors.statusDanger;
        let approveOnClick = disabled
            ? () => {}
            : this.props.pendingDecision.bind(this, 'SelectAll', true);
        let rejectOnClick = disabled
            ? () => {}
            : this.props.pendingDecision.bind(this, 'SelectAll', false);
        return (
            <tr data-testid='pending-approval-table-header'>
                <SelectAllRejectTableHeaderCheckBox>
                    <CheckBox
                        checked={checked}
                        name='checkbox-header'
                        id='select-all-header'
                        onChange={() => {
                            this.setState({
                                checked: !this.state.checked,
                            });
                            this.props.onChange();
                        }}
                    />
                </SelectAllRejectTableHeaderCheckBox>
                <TableHeaderSelectAll>
                    <div> Select All </div>
                </TableHeaderSelectAll>
                <TableHeader />
                <TableHeader />
                <TableHeader colSpan={2} />
                <TableHeader />
                <TableHeader />
                <SelectAllBoxTableHeader>
                    <StyledTextArea
                        height='37px'
                        placeholder='Justification'
                        rows='1'
                        width='100%'
                        disabled={disabled}
                        onChange={(event) => {
                            this.props.auditRefChange('SelectAll', event);
                        }}
                    />
                    {this.props.auditRefMissing ? (
                        <ErrorDiv>Justification is Required</ErrorDiv>
                    ) : null}
                </SelectAllBoxTableHeader>
                <SelectAllBoxTableHeader>
                    <FlatPickrInputDiv disabled={disabled}>
                        <FlatPicker
                            onChange={(date) => {
                                this.props.dateChange('SelectAll', date);
                            }}
                            clear={this.props.clear}
                            id='workflowHeader'
                            nomargin={true}
                        />
                    </FlatPickrInputDiv>
                </SelectAllBoxTableHeader>
                <SelectAllApproveTableHeader>
                    <Icon
                        icon={'check-circle'}
                        onClick={approveOnClick}
                        color={approveColor}
                        isLink
                        size={'1.25em'}
                        verticalAlign={'text-bottom'}
                    />
                </SelectAllApproveTableHeader>
                <SelectAllRejectTableHeader>
                    <Icon
                        icon={'decline'}
                        onClick={rejectOnClick}
                        color={rejectColor}
                        isLink
                        size={'1.25em'}
                        verticalAlign={'text-bottom'}
                    />
                </SelectAllRejectTableHeader>
            </tr>
        );
    }
}
