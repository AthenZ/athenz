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
import AddModal from '../modal/AddModal';
import FlatPicker from '../flatpicker/FlatPicker';
import Input from '../denali/Input';
import InputLabel from '../denali/InputLabel';
import { colors } from '../denali/styles';
import DateUtils from '../utils/DateUtils';
import { splitByType } from './selfServiceUtils';

const SectionsDiv = styled.div`
    background-color: ${colors.white};
    text-align: left;
    width: 760px;
`;

const Description = styled.div`
    color: ${colors.grey700};
    font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    line-height: 1.45;
    padding: 0 30px 16px;
`;

const SectionDiv = styled.div`
    align-items: flex-start;
    display: flex;
    flex-flow: row nowrap;
    padding: 10px 30px;
`;

const StyledInputLabel = styled(InputLabel)`
    flex: 0 0 110px;
    font-weight: 600;
    line-height: 36px;
`;

const ContentDiv = styled.div`
    display: flex;
    flex: 1 1;
    flex-flow: column nowrap;
`;

const StyledInput = styled(Input)`
    width: 100%;
`;

const LockedInput = styled(Input)`
    width: 100%;
    & input[disabled] {
        background-color: ${colors.grey300};
        border-bottom: 2px solid ${colors.grey400};
        color: ${colors.grey600};
        cursor: not-allowed;
    }
`;

const SelectedList = styled.div`
    display: grid;
    gap: 6px 24px;
    grid-template-columns: minmax(0, 1fr) auto;
    width: 100%;
`;

const SelectedName = styled.div`
    color: ${colors.grey800};
    font: 600 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
`;

const SelectedDomain = styled.div`
    color: ${colors.grey600};
    font: 300 12px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    line-height: 20px;
`;

const Note = styled.div`
    color: ${colors.grey600};
    font: 300 12px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    padding: 0 30px 8px 140px;
`;

const FlatPickrInputDiv = styled.div`
    margin-right: 10px;
    max-width: 500px;
    width: 260px;
    & > div input {
        background-color: rgba(53, 112, 244, 0.05);
        border-color: transparent;
        border-image: initial;
        border-radius: 2px;
        border-style: solid;
        border-width: 2px;
        box-shadow: none;
        color: rgb(48, 48, 48);
        flex: 1 0 auto;
        font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
        margin: 0 10px 0 0;
        min-width: 50px;
        outline: none;
        padding: 0.6em 12px;
        position: relative;
        text-align: left;
        width: 80%;
    }
`;

const DatesRow = styled.div`
    display: flex;
    flex: 1 1;
    flex-flow: row nowrap;
`;

const modalTitle = (items) => {
    if (items.length === 1) {
        const category = items[0].type === 'group' ? 'group' : 'role';
        return `Add Member to ${category}: ${items[0].name}`;
    }
    const { roles, groups } = splitByType(items);
    if (roles.length && !groups.length) {
        return 'Add Member to Roles';
    }
    if (groups.length && !roles.length) {
        return 'Add Member to Groups';
    }
    return 'Add Member to Roles & Groups';
};

export default class RequestAccessModal extends React.Component {
    constructor(props) {
        super(props);
        this.dateUtils = new DateUtils();
        this.onSubmit = this.onSubmit.bind(this);
        this.state = {
            justification: '',
            memberExpiry: '',
            memberReviewReminder: '',
            errorMessage: null,
        };
    }

    inputChanged(key, evt) {
        this.setState({ [key]: evt.target.value, errorMessage: null });
    }

    onSubmit() {
        const justification = this.state.justification?.trim();
        if (!justification) {
            this.setState({
                errorMessage: 'Justification is required to request access.',
            });
            return;
        }
        this.props.onSubmit({
            justification,
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
        });
    }

    renderSelected(label, list) {
        if (!list.length) {
            return null;
        }
        return (
            <SectionDiv>
                <StyledInputLabel>{label}</StyledInputLabel>
                <ContentDiv>
                    <SelectedList data-testid='selected-resources'>
                        {list.map((item) => (
                            <React.Fragment
                                key={`${item.domainName}:${item.type}.${item.name}`}
                            >
                                <SelectedName>{item.name}</SelectedName>
                                <SelectedDomain>
                                    {item.domainName}
                                </SelectedDomain>
                            </React.Fragment>
                        ))}
                    </SelectedList>
                </ContentDiv>
            </SectionDiv>
        );
    }

    render() {
        const items = this.props.items ?? [];
        if (!items.length) {
            return null;
        }
        const { roles, groups } = splitByType(items);
        const includesRoles = roles.length > 0;
        const single = items.length === 1 ? items[0] : null;
        const sections = (
            <SectionsDiv data-testid='request-access-form'>
                {single && <Description>{single.description}</Description>}
                <SectionDiv>
                    <StyledInputLabel htmlFor='self-serve-member'>
                        Member
                    </StyledInputLabel>
                    <ContentDiv>
                        <LockedInput
                            id='self-serve-member'
                            name='self-serve-member'
                            value={this.props.memberName}
                            disabled
                            readOnly
                            fluid
                        />
                    </ContentDiv>
                </SectionDiv>
                {this.renderSelected('Roles', roles)}
                {this.renderSelected('Groups', groups)}
                {includesRoles && (
                    <>
                        <SectionDiv>
                            <StyledInputLabel />
                            <DatesRow>
                                <FlatPickrInputDiv>
                                    <FlatPicker
                                        onChange={(memberExpiry) => {
                                            this.setState({ memberExpiry });
                                        }}
                                        id='self-serve-expiry'
                                        clear={this.state.memberExpiry}
                                    />
                                </FlatPickrInputDiv>
                                <FlatPickrInputDiv>
                                    <FlatPicker
                                        onChange={(memberReviewReminder) => {
                                            this.setState({
                                                memberReviewReminder,
                                            });
                                        }}
                                        placeholder='Reminder (Optional)'
                                        id='self-serve-reminder'
                                        clear={this.state.memberReviewReminder}
                                    />
                                </FlatPickrInputDiv>
                            </DatesRow>
                        </SectionDiv>
                        {groups.length > 0 && (
                            <Note>
                                Expiration and reminder apply to roles only.
                                Groups have no review reminder.
                            </Note>
                        )}
                    </>
                )}
                <SectionDiv>
                    <StyledInputLabel htmlFor='self-serve-justification'>
                        Justification
                    </StyledInputLabel>
                    <ContentDiv>
                        <StyledInput
                            id='self-serve-justification'
                            name='justification'
                            value={this.state.justification}
                            onChange={this.inputChanged.bind(
                                this,
                                'justification'
                            )}
                            autoComplete='off'
                            placeholder='Enter justification here'
                            fluid
                        />
                    </ContentDiv>
                </SectionDiv>
            </SectionsDiv>
        );

        return (
            <AddModal
                isOpen={this.props.isOpen}
                cancel={this.props.onCancel}
                submit={this.onSubmit}
                title={modalTitle(items)}
                errorMessage={
                    this.state.errorMessage || this.props.errorMessage
                }
                sections={sections}
                width='820px'
            />
        );
    }
}
