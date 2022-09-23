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
import AddModal from '../modal/AddModal';
import AddRuleForRoleForm from './AddRuleForRoleForm';
import RequestUtils from '../utils/RequestUtils';
import { addPolicy } from '../../redux/thunks/policies';
import { connect } from 'react-redux';

export class AddPolicyToRole extends React.Component {
    constructor(props) {
        super(props);
        this.onSubmit = this.onSubmit.bind(this);
        this.onChange = this.onChange.bind(this);
        this.state = {
            showModal: !!this.props.showAddPolicy,
            case: false,
        };
    }

    onSubmit() {
        if (!this.state.name || this.state.name === '') {
            this.setState({
                errorMessage: 'Policy name is required.',
            });
            return;
        }

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
            .addPolicy(
                this.props.domain,
                this.state.name,
                this.props.role,
                this.state.resource,
                this.state.action,
                this.state.effect,
                this.state.case,
                this.props._csrf
            )
            .then((data) => {
                this.setState({ showModal: false });
                this.props.onSubmit(`${this.state.name}`, false);
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
            <AddModal
                isOpen={this.state.showModal}
                cancel={this.props.onCancel}
                submit={this.onSubmit}
                title={`Add Policy to ${this.props.domain}`}
                errorMessage={this.state.errorMessage}
                sections={
                    <AddRuleForRoleForm
                        domain={this.props.domain}
                        onChange={this.onChange}
                        isPolicy={true}
                    />
                }
            />
        );
    }
}

const mapDispatchToProps = (dispatch) => ({
    addPolicy: (
        domain,
        policyName,
        role,
        resource,
        action,
        effect,
        caseSensitive,
        _csrf
    ) =>
        dispatch(
            addPolicy(
                domain,
                policyName,
                role,
                resource,
                action,
                effect,
                caseSensitive,
                _csrf
            )
        ),
});

export default connect(null, mapDispatchToProps)(AddPolicyToRole);
