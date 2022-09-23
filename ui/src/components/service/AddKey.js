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
import Color from '../denali/Color';
import RequestUtils from '../utils/RequestUtils';
import { selectIsLoading } from '../../redux/selectors/loading';
import { selectServices } from '../../redux/selectors/services';
import { addKey, deleteService } from '../../redux/thunks/services';
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
            });
            return;
        }

        if (!this.state.keyValue || this.state.keyValue === '') {
            this.setState({
                errorMessage: 'Key Value is required.',
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
                this.props.onSubmit(
                    `${this.state.keyId}-${this.props.service}`,
                    false
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
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
                {this.state.errorMessage && (
                    <ErrorDiv>
                        <Color name={'red600'}>{this.state.errorMessage}</Color>
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
