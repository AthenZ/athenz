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

// NOTE: There should be two ways to use <RadioButtonGroup>:
// 1. Pass in buttons config, which will generate all the radio buttons
// 2. As a render prop (settting render=true), which will provide 'checked' prop
//    to the children. If render=true, it overrides all other props. This is
//    not yet implemented

import React from 'react';
import PropTypes from 'prop-types';
import RadioButton from './RadioButton';
import { css, cx } from '@emotion/css';

const makeCssRadioButtonGroup = (props) => css`
    display: inline-flex;
    flex-flow: ${props.direction === 'horizontal'
        ? 'row nowrap'
        : 'column nowrap'};
    label: button-group;
    & > * {
        flex: 1 0 auto;
    }
`;

/**
 * `denali-react` exposes both `<RadioButtonGroup>` and `<RadioButton>` as
 * exports, but under normal usage, you'll only want to use `<RadioButtonGroup>`
 * and let this library handle all the state changes between linked radio
 * buttons.
 */
class RadioButtonGroup extends React.PureComponent {
    render() {
        const {
            className,
            direction,
            disabled,
            id,
            inputs,
            selectedValue,
            ...rest
        } = this.props;
        const cssProps = { direction };
        const cssRadioButtonGroup = makeCssRadioButtonGroup(cssProps);

        const classNames = cx(
            cssRadioButtonGroup,
            'denali-radiobutton-group',
            className
        );

        const radioButtons = inputs.map((rb, idx) => (
            <RadioButton
                {...rest}
                checked={rb.value === selectedValue}
                disabled={
                    typeof disabled !== 'undefined' ? disabled : rb.disabled
                }
                id={rb.id}
                key={`rb-${idx}`}
                label={rb.label}
                value={rb.value}
            />
        ));
        return (
            <div className={classNames} id={id} data-testid='radiobuttongroup'>
                {radioButtons}
            </div>
        );
    }
}

RadioButtonGroup.propTypes = {
    /** Additonal class to apply to the outer div */
    className: PropTypes.string,
    /** Direction of the radio buttons */
    direction: PropTypes.oneOf(['horizontal', 'vertical']),
    /** If true, all buttons are disabled regardless of individual button config */
    disabled: PropTypes.bool,
    /** ID of the the radio-button group */
    id: PropTypes.string,
    /** Definitions of all the radio buttons */
    inputs: PropTypes.arrayOf(
        PropTypes.shape({
            id: PropTypes.any,
            label: PropTypes.string,
            value: PropTypes.any.isRequired,
            disabled: PropTypes.bool,
        })
    ),
    /** Disable animations / transitions */
    noanim: PropTypes.bool,
    /** Input 'value' that's currently selected (defaults to first button) */
    selectedValue: PropTypes.oneOfType([
        PropTypes.bool,
        PropTypes.number,
        PropTypes.string,
    ]),
};

RadioButtonGroup.defaultProps = {
    direction: 'horizontal',
    noanim: false,
};

export default RadioButtonGroup;
