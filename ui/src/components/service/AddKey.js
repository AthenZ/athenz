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
import AddKeyForm from './AddKeyForm';
import ServiceKeyUtils from '../utils/ServiceKeyUtils';
import styled from '@emotion/styled';
import { colors } from '../denali/styles';
import Button from '../denali/Button';
import RequestUtils from '../utils/RequestUtils';
import ResourceOwnershipModalFeedback from '../resource-ownership/ResourceOwnershipModalFeedback';
import {
    isServiceResourcePublicKeysManaged,
    resolveResourceOwnershipCliOnError,
} from '../utils/resourceOwnership';
import { cliAddPublicKey } from '../utils/zmsCliCommands';
import { selectIsLoading } from '../../redux/selectors/loading';
import { selectServices } from '../../redux/selectors/services';
import { addKey } from '../../redux/thunks/services';
import { connect } from 'react-redux';

const SectionsDiv = styled.div`
    width: 100%;
    text-align: left;
    background-color: ${colors.white};
`;

const ModifiedButton = styled(Button)`
    min-width: 8.5em;
    min-height: 1em;
`;

const ButtonDiv = styled.div`
    margin-left: 155px;
`;

const ParentButtonsDiv = styled.div`
    background-color: ${colors.white};
`;

const ErrorDiv = styled.div`
    margin-left: 155px;
`;

class AddKey extends React.Component {
    constructor(props) {
        super(props);
        this.onSubmit = this.onSubmit.bind(this);
        this.onChange = this.onChange.bind(this);
        this.state = {};
    }

    onSubmit() {
        if (!this.state.keyId || this.state.keyId === '') {
            this.setState({
                errorMessage: 'Key Id is required.',
                resourceOwnershipCliCommand: null,
            });
            return;
        }

        if (!this.state.keyValue || this.state.keyValue === '') {
            this.setState({
                errorMessage: 'Key Value is required.',
                resourceOwnershipCliCommand: null,
            });
            return;
        }

        this.props
            .addKey(
                this.props.domain,
                this.props.service,
                this.state.keyId,
                ServiceKeyUtils.y64Encode(
                    ServiceKeyUtils.trimKey(this.state.keyValue)
                ),
                this.props._csrf
            )
            .then(() => {
                this.setState({ resourceOwnershipCliCommand: null });
                this.props.onSubmit(
                    `${this.state.keyId}-${this.props.service}`,
                    false
                );
            })
            .catch((err) => {
                const errMsg = RequestUtils.xhrErrorCheckHelper(err);
                this.setState({
                    errorMessage: errMsg,
                    resourceOwnershipCliCommand:
                        resolveResourceOwnershipCliOnError(
                            isServiceResourcePublicKeysManaged(
                                this.props.resourceOwnership
                            ),
                            err,
                            (zmsUrl) =>
                                cliAddPublicKey(
                                    this.props.domain,
                                    this.props.service,
                                    this.state.keyId,
                                    '<path-to-public-key.pem>',
                                    null,
                                    zmsUrl
                                )
                        ),
                });
            });
    }

    onChange(key, value) {
        this.setState({ [key]: value });
    }

    render() {
        return (
            <SectionsDiv autoComplete={'off'} data-testid='add-key'>
                <AddKeyForm
                    domain={this.props.domain}
                    onChange={this.onChange}
                />
                {(this.state.errorMessage ||
                    this.state.resourceOwnershipCliCommand) && (
                    <ErrorDiv>
                        <ResourceOwnershipModalFeedback
                            errorMessage={this.state.errorMessage}
                            resourceOwnershipCliCommand={
                                this.state.resourceOwnershipCliCommand
                            }
                            errorTestId='error-message'
                        />
                    </ErrorDiv>
                )}
                <ParentButtonsDiv>
                    <ButtonDiv>
                        <ModifiedButton onClick={this.onSubmit}>
                            Submit
                        </ModifiedButton>
                        <ModifiedButton secondary onClick={this.props.cancel}>
                            Cancel
                        </ModifiedButton>
                    </ButtonDiv>
                </ParentButtonsDiv>
            </SectionsDiv>
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        isLoading: selectIsLoading(state),
        services: selectServices(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    addKey: (
        domainName,
        serviceName,
        keyId,
        keyValue,
        _csrf,
        onSuccess,
        onFail
    ) =>
        dispatch(
            addKey(
                domainName,
                serviceName,
                keyId,
                keyValue,
                _csrf,
                onSuccess,
                onFail
            )
        ),
});

export default connect(mapStateToProps, mapDispatchToProps)(AddKey);
