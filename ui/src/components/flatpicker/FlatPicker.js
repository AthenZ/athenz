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
import flatpickr from 'flatpickr';
import DateUtils from '../utils/DateUtils';
import { colors } from '../denali/styles';
import Icon from '../denali/icons/Icon';
import styled from '@emotion/styled';
import { ADD_ROLE_EXPIRATION_PLACEHOLDER } from '../constants/constants';

const DateClearAnchor = styled.a`
    margin-left: -7px;
    margin-top: 10px !important;
`;

const Div = styled.div`
    display: flex;
`;

export default class FlatPicker extends React.Component {
    constructor(props) {
        super(props);
        this.clearDate = React.createRef();
        this.dateUtils = new DateUtils();
        this.onChange = this.onChange.bind(this);
        this.onClose = this.onClose.bind(this);
        this.state = {
            minDate: this.props.minDate
                ? this.props.minDate
                : this.dateUtils.getDatePlusFourHours(
                      new Date(),
                      this.dateUtils.getCurrentTimeZone()
                  ),
            maxDate: this.props.maxDate ? this.props.maxDate : null,
            placeholder: this.props.placeholder
                ? this.props.placeholder
                : ADD_ROLE_EXPIRATION_PLACEHOLDER,
            value: this.props.value
                ? this.dateUtils.uxDatetimeToRDLTimestamp(this.props.value)
                : '',
        };
        this.onChangeDate = '';
        this.onCloseDate = '';
    }

    onChange(selectedDates, dateStr, instance) {
        this.onChangeDate = dateStr;
        if (dateStr === '') {
            this.props.onChange(selectedDates);
        }
    }

    onClose(selectedDates, dateStr, instance) {
        this.onCloseDate = dateStr;
        if (this.onChangeDate === this.onCloseDate || !this.clearDate.current) {
            if (dateStr !== '') {
                this.props.onChange(selectedDates);
            }
        } else {
            this.clearDate.current.click();
        }
    }

    componentDidUpdate = (prevProps) => {
        if (
            prevProps.clear !== '' &&
            this.props.clear === '' &&
            !this.props.shouldNotClear &&
            this.clearDate.current
        ) {
            this.clearDate.current.click();
        }
    };

    componentDidMount() {
        let fpClass = this.props.id ? 'fp-' + this.props.id : 'flatpickr';
        flatpickr('.' + fpClass, {
            onChange: this.onChange,
            onClose: this.onClose,
            enableTime: true,
            altInput: true,
            altFormat: 'Y-m-d h:i K',
            minDate: this.state.minDate,
            defaultDate: this.state.value,
            wrap: true,
        });
    }

    render() {
        let fpClass = this.props.id ? 'fp-' + this.props.id : 'flatpickr';
        return (
            <Div className={fpClass}>
                <input
                    type='date'
                    data-testid='flatPicker'
                    placeholder={this.state.placeholder}
                    defaultValue={this.state.value}
                    data-input=''
                />
                {!this.props.shouldNotClear && this.props.nomargin && (
                    <a data-clear='' ref={this.clearDate}>
                        <Icon
                            icon={'close'}
                            color={colors.icons}
                            isLink
                            size={'1.25em'}
                            verticalAlign={'text-bottom'}
                            onHover={'clear'}
                        />
                    </a>
                )}
                {!this.props.shouldNotClear && !this.props.nomargin && (
                    <DateClearAnchor data-clear='' ref={this.clearDate}>
                        <Icon
                            icon={'close'}
                            color={colors.icons}
                            isLink
                            size={'1.25em'}
                            verticalAlign={'text-bottom'}
                            onHover={'clear'}
                        />
                    </DateClearAnchor>
                )}
            </Div>
        );
    }
}
