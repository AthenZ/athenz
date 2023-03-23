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
import TextArea from '../denali/TextArea';
import Icon from '../denali/icons/Icon';
import FlatPicker from '../flatpicker/FlatPicker';
import CheckBox from '../denali/CheckBox';
import { PENDING_APPROVAL_KEY_ENUM } from '../constants/constants';
import { rgba } from 'polished';

const SelectAllRejectTableHeader = styled.th`
    border-bottom: 1px solid ${colors.grey500};
    color: ${colors.grey600};
    font-weight: 600;
    vertical-align: middle;
    text-transform: uppercase;
    text-align: center;
    border-right: none;
    position: absolute;
    width: 6em;
    right: 0em;
    z-index: 1;
    height: 42px;
    background-color: rgba(255, 255, 255, 1);
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
    border-bottom: 1px solid ${colors.grey500};
    color: ${colors.grey600};
    font-weight: 600;
    vertical-align: middle;
    text-transform: uppercase;
    text-align: center;
    position: absolute;
    width: 6em;
    right: 6em;
    z-index: 1;
    height: 42px;
    background-color: rgba(255, 255, 255, 1);
    padding: 5px 0 5px 15px;
`;

const FlatPickrInputDiv = styled.div`
    & > div input {
        position: relative;
        font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
        background-color: ${(props) =>
            props.disabled ? rgba(48, 48, 48, 0.05) : rgba(48, 48, 48, 0.25)};
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
        margin: 5px 7px 0px 0px;
        outline: none;
        padding: 0.6em 12px;
        transition: background-color 0.2s ease-in-out 0s,
            color 0.2s ease-in-out 0s, border 0.2s ease-in-out 0s;
        width: 10em;
    }
`;

const TableHeader = styled.th`
    border-bottom: 2px solid ${colors.grey500};
    color: ${colors.grey600};
    font-weight: 600;
    font-size: 1.2rem;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 15px;
    text-align: left;
    white-space: nowrap;
`;

const TableHeaderSelectAll = styled.th`
    border-bottom: 2px solid ${colors.grey500};
    color: ${colors.grey600};
    font-weight: 600;
    font-size: 1.2rem;
    vertical-align: middle;
    text-transform: uppercase;
    padding: 5px 0 5px 0px;
    text-align: left;
`;

const SelectAllBoxTableHeader = styled.th`
    border-bottom: 2px solid ${colors.grey500};
    font-weight: 600;
    font-size: 1.2rem;
    vertical-align: bottom;
    padding: 5px 0 5px 15px;
    text-align: left;
`;

const AllRejectApproveIcon = styled.div`
    margin-top: 10px;
`;

export default class PendingApprovalTableHeader extends React.Component {
    constructor(props) {
        super(props);
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
            : this.props.pendingDecision.bind(
                  this,
                  PENDING_APPROVAL_KEY_ENUM.SELECTALL,
                  true
              );
        let rejectOnClick = disabled
            ? () => {}
            : this.props.pendingDecision.bind(
                  this,
                  PENDING_APPROVAL_KEY_ENUM.SELECTALL,
                  false
              );
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
                {this.props.view === 'admin' && <TableHeader />}
                <TableHeader />
                <TableHeader colSpan={4} />
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
                            this.props.auditRefChange(
                                PENDING_APPROVAL_KEY_ENUM.SELECTALL,
                                event
                            );
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
                                this.props.dateChange(
                                    PENDING_APPROVAL_KEY_ENUM.SELECTALL,
                                    date,
                                    'expiry'
                                );
                            }}
                            clearExpiry={this.props.clearExpiry}
                            id='workflowHeaderExpiry'
                        />
                    </FlatPickrInputDiv>
                </SelectAllBoxTableHeader>
                <SelectAllBoxTableHeader>
                    <FlatPickrInputDiv disabled={disabled}>
                        <FlatPicker
                            onChange={(date) => {
                                this.props.dateChange(
                                    PENDING_APPROVAL_KEY_ENUM.SELECTALL,
                                    date,
                                    'reviewReminder'
                                );
                            }}
                            placeholder={'Reminder (Optional)'}
                            clearReviewReminder={this.props.clearReviewReminder}
                            id='workflowHeaderReviewReminder'
                        />
                    </FlatPickrInputDiv>
                </SelectAllBoxTableHeader>
                <SelectAllApproveTableHeader>
                    <AllRejectApproveIcon>
                        <Icon
                            icon={'check-circle'}
                            onClick={approveOnClick}
                            color={approveColor}
                            isLink
                            size={'1.25em'}
                            verticalAlign={'text-bottom'}
                        />
                    </AllRejectApproveIcon>
                </SelectAllApproveTableHeader>
                <SelectAllRejectTableHeader>
                    <AllRejectApproveIcon>
                        <Icon
                            icon={'decline'}
                            onClick={rejectOnClick}
                            color={rejectColor}
                            isLink
                            size={'1.25em'}
                            verticalAlign={'text-bottom'}
                        />
                    </AllRejectApproveIcon>
                </SelectAllRejectTableHeader>
            </tr>
        );
    }
}
