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
import AddModal from '../modal/AddModal';
import FlatPicker from '../flatpicker/FlatPicker';
import { colors } from '../denali/styles';
import Input from '../denali/Input';
import InputLabel from '../denali/InputLabel';
import styled from '@emotion/styled';
import Checkbox from '../denali/CheckBox';
import DateUtils from '../utils/DateUtils';
import NameUtils from '../utils/NameUtils';
import RequestUtils from '../utils/RequestUtils';

const SectionsDiv = styled.div`
    width: 800px;
    text-align: left;
    background-color: ${colors.white};
`;

const SectionDiv = styled.div`
    align-items: flex-start;
    display: flex;
    flex-flow: row nowrap;
    padding: 10px 30px;
`;

const ContentDiv = styled.div`
    flex: 1 1;
    display: flex;
    flex-flow: row wrap;
`;

const StyledInputLabel = styled(InputLabel)`
    flex: 0 0 150px;
    font-weight: 600;
    line-height: 36px;
`;

const StyledInput = styled(Input)`
    max-width: 500px;
    margin-right: 10px;
    width: 300px;
`;

const FlatPickrInputDiv = styled.div`
    margin-right: 10px;
    max-width: 500px;
    width: 260px;
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
        outline: none;
        padding: 0.6em 12px;
        transition: background-color 0.2s ease-in-out 0s,
            color 0.2s ease-in-out 0s, border 0.2s ease-in-out 0s;
        width: 80%;
    }
`;

const StyledRoleContainer = styled.div`
    width: 100%;
`;

const StyledRole = styled.div`
    background-color: rgba(53, 112, 244, 0.06);
    padding: 10px;
    width: calc(100% - 10px);
`;

const StyledJustification = styled(Input)`
    width: 300px;
    margin-top: 5px;
`;

export default class AddMember extends React.Component {
    constructor(props) {
        super(props);
        this.api = this.props.api;
        this.onSubmit = this.onSubmit.bind(this);
        this.state = {
            showModal: !!this.props.showAddMember,
        };
        this.dateUtils = new DateUtils();
    }

    onSubmit() {
        if (!this.state.memberName || this.state.memberName.trim() === '') {
            this.setState({
                errorMessage: 'Member name is required.',
            });
            return;
        }

        if (
            this.props.justificationRequired &&
            (this.state.justification === undefined ||
                this.state.justification.trim() === '')
        ) {
            this.setState({
                errorMessage: 'Justification is required to add a member.',
            });
            return;
        }

        let member = {
            memberName: this.state.memberName,
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
        // send api call and then reload existing members component
        this.api
            .addMember(
                this.props.domain,
                this.props.role,
                this.state.memberName,
                member,
                this.state.justification
                    ? this.state.justification
                    : 'added using Athenz UI',
                this.props._csrf
            )
            .then(() => {
                this.setState({
                    showModal: false,
                    justification: '',
                });
                this.props.onSubmit(
                    `Successfully added ${this.state.memberName} to role: ${this.props.role}`
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    inputChanged(key, evt) {
        this.setState({ [key]: evt.target.value });
    }

    render() {
        let sections = (
            <SectionsDiv autoComplete={'off'} data-testid='add-member-form'>
                <SectionDiv>
                    <StyledInputLabel htmlFor='member-name'>
                        Member
                    </StyledInputLabel>
                    <ContentDiv>
                        <StyledInput
                            id='member-name'
                            name='member-name'
                            value={this.state.memberName}
                            onChange={this.inputChanged.bind(
                                this,
                                'memberName'
                            )}
                            placeholder='user.<shortid> or <domain>.<service> or unix.<group>'
                        />
                        <FlatPickrInputDiv>
                            <FlatPicker
                                onChange={(memberExpiry) => {
                                    this.setState({ memberExpiry });
                                }}
                                id='addMember'
                                clear={this.state.memberExpiry}
                            />
                        </FlatPickrInputDiv>
                        {this.props.justificationRequired && (
                            <StyledJustification
                                id='justification'
                                name='justification'
                                value={this.state.justification}
                                onChange={this.inputChanged.bind(
                                    this,
                                    'justification'
                                )}
                                autoComplete={'off'}
                                placeholder='Enter justification here'
                            />
                        )}
                    </ContentDiv>
                </SectionDiv>
            </SectionsDiv>
        );

        return (
            <AddModal
                isOpen={this.state.showModal}
                cancel={this.props.onCancel}
                submit={this.onSubmit}
                title={'Add Member to Role:'}
                errorMessage={this.state.errorMessage}
                sections={sections}
            />
        );
    }
}
