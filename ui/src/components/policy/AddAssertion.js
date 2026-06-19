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
import AddRuleForm from './AddRuleForm';
import Button from '../denali/Button';
import { colors } from '../denali/styles';
import RequestUtils from '../utils/RequestUtils';
import { addAssertionPolicyVersion } from '../../redux/thunks/policies';
import { connect } from 'react-redux';
import ResourceOwnershipModalFeedback from '../resource-ownership/ResourceOwnershipModalFeedback';
import {
    isPolicyResourceManaged,
    resolveResourceOwnershipCliOnError,
} from '../utils/resourceOwnership';
import {
    cliAddAssertionPolicyVersion,
    formatAssertionWords,
} from '../utils/zmsCliCommands';

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

class AddAssertion extends React.Component {
    constructor(props) {
        super(props);
        this.onChange = this.onChange.bind(this);
        this.onSubmit = this.onSubmit.bind(this);
        this.state = {
            case: false,
            resourceOwnershipCliCommand: null,
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

        if (!this.state.role || this.state.role === '') {
            this.setState({
                errorMessage: 'Role must be selected in the dropdown.',
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
            .addAssertionPolicyVersion(
                this.props.domain,
                this.props.name,
                this.props.version,
                this.state.role,
                this.state.resource,
                this.state.action,
                this.state.effect,
                this.state.case,
                this.props._csrf
            )
            .then((data) => {
                this.props.submit(
                    `${this.props.name}-${this.props.version}-${data.role}-${data.resource}-${data.action}`,
                    false
                );
            })
            .catch((err) => {
                const errMsg = RequestUtils.xhrErrorCheckHelper(err);
                this.setState({
                    errorMessage: errMsg,
                    resourceOwnershipCliCommand:
                        resolveResourceOwnershipCliOnError(
                            isPolicyResourceManaged(
                                this.props.resourceOwnership
                            ),
                            err,
                            (zmsUrl) => {
                                const assertion = {
                                    effect: this.state.effect,
                                    action: this.state.action,
                                    role: this.state.role,
                                    resource: this.state.resource,
                                };
                                const words = formatAssertionWords(
                                    this.props.domain,
                                    assertion
                                );
                                return cliAddAssertionPolicyVersion(
                                    this.props.domain,
                                    this.props.name,
                                    this.props.version,
                                    words,
                                    null,
                                    !!this.state.case,
                                    zmsUrl
                                );
                            }
                        ),
                });
            });
    }

    render() {
        return (
            <StyledDiv data-testid='add-assertion'>
                <AddRuleForm
                    onChange={this.onChange}
                    domain={this.props.domain}
                    id={this.props.name + '-' + this.props.version}
                />
                {(this.state.errorMessage ||
                    this.state.resourceOwnershipCliCommand) && (
                    <ErrorDiv>
                        <ResourceOwnershipModalFeedback
                            errorMessage={this.state.errorMessage}
                            resourceOwnershipCliCommand={
                                this.state.resourceOwnershipCliCommand
                            }
                        />
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
    addAssertionPolicyVersion: (
        domain,
        policyName,
        version,
        role,
        resource,
        action,
        effect,
        caseSensitive,
        _csrf
    ) =>
        dispatch(
            addAssertionPolicyVersion(
                domain,
                policyName,
                version,
                role,
                resource,
                action,
                effect,
                caseSensitive,
                _csrf
            )
        ),
});

export default connect(null, mapDispatchToProps)(AddAssertion);
