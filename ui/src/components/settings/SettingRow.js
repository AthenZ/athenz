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
import Switch from '../denali/Switch';
import Input from '../denali/Input';
import InputDropdown from '../denali/InputDropdown';

const TDStyled = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
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

const StyledDiv = styled.div`
    display: flex;
`;

const SettingInput = styled(Input)`
    margin-top: 5px;
`;

const StyledInputDropDown = styled(InputDropdown)`
    margin-top: 5px;
    display: block;
`;

export default class SettingRow extends React.Component {
    constructor(props) {
        super(props);
        this.onTimeChange = this.onTimeChange.bind(this);
        this.onDropDownChange = this.onDropDownChange.bind(this);
        this.toggleSwitchButton = this.toggleSwitchButton.bind(this);
        this.onRadioChange = this.onRadioChange.bind(this);
        this.saveJustification = this.saveJustification.bind(this);
        this.api = props.api;
    }

    saveJustification(val) {
        this.setState({ deleteJustification: val });
    }

    toggleSwitchButton(evt) {
        this.props.onValueChange(this.props.name, evt.currentTarget.checked);
    }

    onTimeChange(evt) {
        this.props.onValueChange(this.props.name, evt.target.value);
    }

    onDropDownChange(evt) {
        let value = evt ? evt.value : '';
        this.props.onValueChange(this.props.name, value);
    }

    onRadioChange(event) {
        if (event.target.value) {
            this.props.onValueChange(this.props.name, event.target.value);
        }
    }

    numRestricted(event) {
        const re = /[0-9]+/g;
        if (!re.test(event.key)) {
            event.preventDefault();
        }
    }

    getSettingButton() {
        switch (this.props.type) {
            case 'switch':
                return (
                    <Switch
                        name={'setting' + this.props.name}
                        value={this.props.value}
                        checked={this.props.value}
                        onChange={this.toggleSwitchButton}
                    />
                );
            case 'input':
                return (
                    <StyledDiv>
                        <SettingInput
                            pattern='[0-9]*'
                            placeholder={this.props.unit}
                            fluid
                            id={'setting-' + this.props.name}
                            onChange={this.onTimeChange}
                            onKeyPress={this.numRestricted}
                            value={this.props.value}
                        />
                    </StyledDiv>
                );
            case 'dropdown':
                return (
                    <StyledDiv>
                        <StyledInputDropDown
                            fluid
                            name={'setting-' + this.props.name}
                            options={this.props.options}
                            placeholder={this.props.placeholder}
                            filterable
                            onChange={this.onDropDownChange}
                            defaultSelectedValue={this.props.value}
                        />
                    </StyledDiv>
                );
        }
    }

    render() {
        let rows = [];
        let left = 'left';
        let color = this.props.color;
        let label = this.props.label;

        if (this.props.unit) {
            label += this.props.unit ? ` (${this.props.unit})` : '';
        }
        let name = this.props.name;

        let button = this.getSettingButton();

        rows.push(
            <TrStyled key={name} data-testid='setting-row'>
                <TDStyled color={color} align={left}>
                    {label}
                </TDStyled>
                <TDStyled color={color} align={left}>
                    {button}
                </TDStyled>
                <TDStyled color={color} align={left}>
                    {this.props.desc}
                </TDStyled>
            </TrStyled>
        );

        return rows;
    }
}
