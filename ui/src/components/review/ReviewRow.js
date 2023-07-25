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
import RadioButton from '../denali/RadioButton';
import DateUtils from '../utils/DateUtils';

const TDStyled = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
    border-bottom: 1px solid #d5d5d5;
`;

const TrStyled = styled.tr`
    box-sizing: border-box;
    margin-top: 10px;
    box-shadow: 0 1px 4px #d9d9d9;
    border: 1px solid #fff;
    -webkit-border-image: none;
    border-image: none;
    -webkit-border-image: initial;
    border-image: initial;
    height: 50px;
`;

export default class ReviewRow extends React.Component {
    constructor(props) {
        super(props);
        this.api = this.props.api;
        this.onReview = this.onReview.bind(this);
        let selectedOption = 'extend';
        this.state = {
            selectedOption: selectedOption,
        };
        this.localDate = new DateUtils();
    }

    onReview(evt) {
        switch (evt.target.value) {
            case 'extend':
                this.props.onUpdate('extend', this.props.details.memberName);
                break;
            case 'delete':
                this.props.onUpdate('delete', this.props.details.memberName);
                break;
            case 'no-action':
                this.props.onUpdate('no-action', this.props.details.memberName);
                break;
            default:
                break;
        }
        this.setState({
            selectedOption: evt.target.value,
        });
    }

    componentDidUpdate = (prevProps) => {
        if (prevProps.submittedReview !== this.props.submittedReview) {
            this.setState({
                selectedOption: 'extend',
            });
        }
    };

    render() {
        let rows = [];
        let left = 'left';
        let center = 'center';
        let member = this.props.details;
        let color = this.props.color;
        let exp = member.expiration
            ? this.localDate.getLocalDate(
                  member.expiration,
                  this.props.timeZone,
                  this.props.timeZone
              )
            : 'N/A';
        let reminder = member.reviewReminder
            ? this.localDate.getLocalDate(
                  member.reviewReminder,
                  this.props.timeZone,
                  this.props.timeZone
              )
            : 'N/A';

        rows.push(
            <TrStyled key={this.props.idx} data-testid='review-row'>
                <TDStyled color={color} align={left}>
                    {member.memberName}
                </TDStyled>
                <TDStyled color={color} align={left}>
                    {member.memberFullName}
                </TDStyled>
                {this.props.category === 'group' && (
                    <TDStyled color={color} align={left} colSpan={2}>
                        {exp}
                    </TDStyled>
                )}
                {this.props.category === 'role' && (
                    <TDStyled color={color} align={left}>
                        {exp}
                    </TDStyled>
                )}
                {this.props.category === 'role' && (
                    <TDStyled color={color} align={left}>
                        {reminder}
                    </TDStyled>
                )}
                <TDStyled color={color} align={center}>
                    <RadioButton
                        name={this.props.collection + this.props.idx}
                        value='extend'
                        checked={this.state.selectedOption === 'extend'}
                        onChange={this.onReview}
                    />
                </TDStyled>
                <TDStyled color={color} align={center}>
                    <RadioButton
                        name={this.props.collection + this.props.idx}
                        value='no-action'
                        checked={this.state.selectedOption === 'no-action'}
                        onChange={this.onReview}
                    />
                </TDStyled>
                <TDStyled color={color} align={center}>
                    <RadioButton
                        name={this.props.collection + this.props.idx}
                        value='delete'
                        checked={this.state.selectedOption === 'delete'}
                        onChange={this.onReview}
                    />
                </TDStyled>
            </TrStyled>
        );
        return rows;
    }
}
