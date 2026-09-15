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
import InputLabel from '../denali/InputLabel';
import { colors } from '../denali/styles';
import DateUtils from '../utils/DateUtils';

const SectionsDiv = styled.div`
    background-color: ${colors.white};
    text-align: left;
    width: 600px;
`;

const SectionDiv = styled.div`
    align-items: flex-start;
    display: flex;
    flex-flow: row nowrap;
    padding: 10px 30px;
`;

const StyledInputLabel = styled(InputLabel)`
    flex: 0 0 120px;
    font-weight: 600;
    line-height: 36px;
`;

const ContentDiv = styled.div`
    display: flex;
    flex: 1 1;
    flex-flow: column nowrap;
`;

const ValueText = styled.div`
    color: ${colors.grey800};
    font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    line-height: 36px;
`;

const MaxText = styled.div`
    color: ${colors.grey600};
    font: 300 13px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    padding: 0 30px 12px 150px;
`;

const FlatPickrInputDiv = styled.div`
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

const MS_PER_MIN = 60 * 1000;
const MS_PER_DAY = 24 * 60 * 60 * 1000;

const formatDateTime = (date) =>
    date.toLocaleString('en-GB', {
        day: 'numeric',
        month: 'short',
        year: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
    });

// short, human-friendly "in X" description of how far away the cap is, so the
// max reads naturally whether the window is minutes, hours or months
const humanizeUntil = (date) => {
    const mins = Math.max(
        1,
        Math.round((date.getTime() - Date.now()) / MS_PER_MIN)
    );
    if (mins < 60) {
        return `in ${mins} min`;
    }
    const hours = Math.round(mins / 60);
    if (hours < 48) {
        return `in ${hours} hour${hours === 1 ? '' : 's'}`;
    }
    const days = Math.round(hours / 24);
    return `in ${days} day${days === 1 ? '' : 's'}`;
};

export default class ExtendMembershipModal extends React.Component {
    constructor(props) {
        super(props);
        this.dateUtils = new DateUtils();
        this.onSubmit = this.onSubmit.bind(this);
        this.state = {
            expiry: '',
            errorMessage: null,
        };
    }

    // the effective cap is the earliest of the configured limits: the self-renew
    // window (now + selfRenewMins) and the role/group expiry policy (now +
    // maxExpiryDays, itself the lowest of the role and domain setting). A limit
    // of 0/unset means it does not apply; if neither applies there is no maximum.
    effectiveMaxDate() {
        const item = this.props.item ?? {};
        const caps = [];
        const selfRenewMins = Number(item.selfRenewMins);
        if (item.selfRenew && selfRenewMins > 0) {
            caps.push(Date.now() + selfRenewMins * MS_PER_MIN);
        }
        const maxExpiryDays = Number(item.maxExpiryDays);
        if (maxExpiryDays > 0) {
            caps.push(Date.now() + maxExpiryDays * MS_PER_DAY);
        }
        return caps.length ? new Date(Math.min(...caps)) : null;
    }

    onSubmit() {
        if (!this.state.expiry || this.state.expiry.length === 0) {
            this.setState({
                errorMessage:
                    'Pick a new expiry date to extend your membership.',
            });
            return;
        }
        this.props.onSubmit(
            this.dateUtils.uxDatetimeToRDLTimestamp(this.state.expiry)
        );
    }

    render() {
        const item = this.props.item;
        if (!item) {
            return null;
        }
        const maxDate = this.effectiveMaxDate();
        const typeLabel = item.type === 'group' ? 'Group' : 'Role';
        const sections = (
            <SectionsDiv data-testid='extend-membership-form'>
                <SectionDiv>
                    <StyledInputLabel>{typeLabel}</StyledInputLabel>
                    <ContentDiv>
                        <ValueText>{item.name}</ValueText>
                    </ContentDiv>
                </SectionDiv>
                <SectionDiv>
                    <StyledInputLabel>Domain</StyledInputLabel>
                    <ContentDiv>
                        <ValueText>{item.domainName}</ValueText>
                    </ContentDiv>
                </SectionDiv>
                <SectionDiv>
                    <StyledInputLabel htmlFor='self-serve-extend-expiry'>
                        New expiry
                    </StyledInputLabel>
                    <ContentDiv>
                        <FlatPickrInputDiv>
                            <FlatPicker
                                onChange={(expiry) => {
                                    this.setState({
                                        expiry,
                                        errorMessage: null,
                                    });
                                }}
                                // scope this override to the self-service extend
                                // modal only: the shared FlatPicker otherwise floors
                                // selection at now+4h, which clamps the time wheel on
                                // the current day for short extension windows
                                minDate={new Date()}
                                maxDate={maxDate}
                                id='self-serve-extend-expiry'
                                clear={this.state.expiry}
                            />
                        </FlatPickrInputDiv>
                    </ContentDiv>
                </SectionDiv>
                <MaxText data-testid='extend-max-text'>
                    {maxDate
                        ? `You can extend until ${formatDateTime(
                              maxDate
                          )} (${humanizeUntil(maxDate)}).`
                        : 'No maximum is configured, so you can pick any future date.'}
                </MaxText>
                <MaxText data-testid='extend-approval-note'>
                    If this {typeLabel.toLowerCase()} requires approval, your
                    extension will be submitted as a request instead of applied
                    immediately.
                </MaxText>
            </SectionsDiv>
        );

        return (
            <AddModal
                isOpen={this.props.isOpen}
                cancel={this.props.onCancel}
                submit={this.onSubmit}
                title={`Extend membership: ${item.name}`}
                errorMessage={
                    this.state.errorMessage || this.props.errorMessage
                }
                sections={sections}
                width='660px'
            />
        );
    }
}
