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
import Input from '../denali/Input';
import Button from '../denali/Button';
import FlatPicker from '../flatpicker/FlatPicker';
import DateUtils from '../utils/DateUtils';
import Color from '../denali/Color';
import RequestUtils from '../utils/RequestUtils';
import NameUtils from '../utils/NameUtils';

const SectionsDiv = styled.div`
    width: 100%;
    text-align: left;
    background-color: ${(props) => props.color};
    display: grid;
    grid-gap: 24px;
    grid-template-columns: 23% 20% 20% 20% 10%;
`;

const StyledInputMember = styled(Input)`
    width: 100%;
    margin: 5px;
`;

const StyledJustification = styled(Input)`
    width: 100%;
    margin: 5px;
    margin-left: 2px;
`;

const ButtonDiv = styled.div`
    justify-self: end;
`;

const ButtonWithJustificationDiv = styled.div`
    justify-self: end;
`;
const StyledButton = styled(Button)`
    width: 125px;
`;

const FlatPickrInputDiv = styled.div`
    & > div input {
        position: relative;
        font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
        background-color: rgba(53, 112, 244, 0.05);
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
        margin: 0;
        margin-right: 10px;
        margin-top: 5px;
        outline: none;
        padding: 0.6em 12px;
        transition: background-color 0.2s ease-in-out 0s,
            color 0.2s ease-in-out 0s, border 0.2s ease-in-out 0s;
        width: 80%;
    }
`;

export default class AddMemberForm extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.addMember = this.addMember.bind(this);
        this.state = {
            newMember: '',
            memberExpiry: '',
            memberReviewReminder: '',
            justification: undefined,
        };
        this.dateUtils = new DateUtils();
    }

    inputChanged(key, evt) {
        if (evt.target) {
            this.setState({ [key]: evt.target.value });
        } else {
            this.setState({ [key]: evt ? evt : '' });
        }
    }

    addMember() {
        let member = {
            memberName: this.state.newMember,
            expiration:
                this.state.memberExpiry && this.state.memberExpiry.length > 0
                    ? this.dateUtils.uxDatetimeToRDLTimestamp(
                          this.state.memberExpiry
                      )
                    : '',
            reviewReminder:
                this.state.memberReviewReminder &&
                this.state.memberReviewReminder.length > 0
                    ? this.dateUtils.uxDatetimeToRDLTimestamp(
                          this.state.memberReviewReminder
                      )
                    : '',
        };
        if (
            this.props.justificationRequired &&
            (this.state.justification === undefined ||
                (this.state.justification &&
                    this.state.justification.trim() === ''))
        ) {
            this.setState({
                errorMessage: 'Justification is required to add a member.',
            });
            return;
        } else {
            this.setState({
                errorMessage: null,
            });
        }
        // send api call and then reload existing members component
        let newMember = this.state.newMember;
        this.api
            .addMember(
                this.props.domain,
                this.props.role,
                this.state.newMember,
                member,
                this.state.justification
                    ? this.state.justification
                    : 'added using Athenz UI',
                this.props._csrf
            )
            .then(() => {
                this.setState({
                    newMember: '',
                    memberExpiry: '',
                    memberReviewReminder: '',
                    justification: '',
                });
                this.props.onChange(
                    `Successfully added member ${newMember} to the role ${this.props.role}.`
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    render() {
        let memberChanged = this.inputChanged.bind(this, 'newMember');
        let memberExpiryChanged = this.inputChanged.bind(this, 'memberExpiry');
        let memberReviewReminderChanged = this.inputChanged.bind(
            this,
            'memberReviewReminder'
        );

        return (
            <SectionsDiv autoComplete={'off'} data-testid='add-member-form'>
                <div>
                    <div>
                        <StyledInputMember
                            id='add-member'
                            name='add-member'
                            value={this.state.newMember}
                            onChange={memberChanged}
                            autoComplete={'off'}
                            placeholder='user.<shortid> or <domain>.<service>'
                        />
                        {this.state.errorMessage && (
                            <Color name={'red600'}>
                                {this.state.errorMessage}
                            </Color>
                        )}
                    </div>
                </div>
                <div>
                    <FlatPickrInputDiv>
                        <FlatPicker
                            onChange={memberExpiryChanged}
                            clear={this.state.memberExpiry}
                            id={NameUtils.getFlatPickrKey(this.props.role)}
                        />
                    </FlatPickrInputDiv>
                </div>
                <div>
                    <FlatPickrInputDiv>
                        <FlatPicker
                            onChange={memberReviewReminderChanged}
                            clear={this.state.memberReviewReminder}
                            placeholder='Reminder (Optional)'
                            id={
                                NameUtils.getFlatPickrKey(this.props.role) +
                                '-reminder'
                            }
                        />
                    </FlatPickrInputDiv>
                </div>
                <div>
                    <div>
                        <StyledJustification
                            id='justification'
                            name='justification'
                            value={
                                this.state.justification
                                    ? this.state.justification
                                    : ''
                            }
                            onChange={this.inputChanged.bind(
                                this,
                                'justification'
                            )}
                            autoComplete={'off'}
                            placeholder='Enter justification here'
                        />
                    </div>
                </div>
                {this.props.justificationRequired && (
                    <ButtonWithJustificationDiv>
                        <StyledButton onClick={this.addMember}>
                            Add
                        </StyledButton>
                    </ButtonWithJustificationDiv>
                )}
                {!this.props.justificationRequired && (
                    <ButtonDiv>
                        <StyledButton onClick={this.addMember}>
                            Add
                        </StyledButton>
                    </ButtonDiv>
                )}
            </SectionsDiv>
        );
    }
}
