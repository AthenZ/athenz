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
import AddRuleFormForRole from './AddRuleFormForRole';
import Button from '../denali/Button';
import { colors } from '../denali/styles';
import Color from '../denali/Color';
import RequestUtils from '../utils/RequestUtils';
import { addAssertion } from '../../redux/thunks/policies';
import { connect } from 'react-redux';

const StyledDiv = styled.div`
    background-color: ${colors.white};
`;

const ModifiedButton = styled(Button)`
    min-width: 8.5em;
    min-height: 1em;
`;

const ButtonDiv = styled.div`
    margin-left: 155px;
`;

const ErrorDiv = styled.div`
    margin-left: 155px;
`;

class AddAssertionForRole extends React.Component {
    constructor(props) {
        super(props);
        this.onChange = this.onChange.bind(this);
        this.onSubmit = this.onSubmit.bind(this);
        this.state = {
            case: false,
        };
    }

    onChange(key, value) {
        this.setState({ [key]: value });
    }

    onSubmit() {
        if (!this.state.action || this.state.action === '') {
            this.setState({
                errorMessage: 'Rule action is required.',
            });
            return;
        }

        if (!this.state.resource || this.state.resource === '') {
            this.setState({
                errorMessage: 'Rule resource is required.',
            });
            return;
        }

        this.props
            .addAssertion(
                this.props.domain,
                this.props.name,
                this.props.role,
                this.state.resource,
                this.state.action,
                this.state.effect,
                this.state.case,
                this.props._csrf
            )
            .then(() => {
                this.props.submit(
                    `${this.props.name}-${this.props.role}-${this.state.resource}-${this.state.action}`,
                    false
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    render() {
        return (
            <StyledDiv data-testid='add-assertion-for-role'>
                <AddRuleFormForRole
                    id={this.props.id}
                    onChange={this.onChange}
                    domain={this.props.domain}
                />
                {this.state.errorMessage && (
                    <ErrorDiv>
                        <Color name={'red600'}>{this.state.errorMessage}</Color>
                    </ErrorDiv>
                )}
                <ButtonDiv>
                    <ModifiedButton onClick={this.onSubmit}>
                        Submit
                    </ModifiedButton>
                    <ModifiedButton secondary onClick={this.props.cancel}>
                        Cancel
                    </ModifiedButton>
                </ButtonDiv>
            </StyledDiv>
        );
    }
}

const mapDispatchToProps = (dispatch) => ({
    addAssertion: (
        domainName,
        name,
        roleName,
        resource,
        action,
        effect,
        caseSensitive,
        _csrf
    ) =>
        dispatch(
            addAssertion(
                domainName,
                name,
                roleName,
                resource,
                action,
                effect,
                caseSensitive,
                _csrf
            )
        ),
});

export default connect(null, mapDispatchToProps)(AddAssertionForRole);
