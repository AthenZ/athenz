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
import AddModal from '../modal/AddModal';
import AddServiceForm from './AddServiceForm';
import ServiceKeyUtils from '../utils/ServiceKeyUtils';
import RequestUtils from '../utils/RequestUtils';

export default class AddService extends React.Component {
    constructor(props) {
        super(props);
        this.api = this.props.api;
        this.onSubmit = this.onSubmit.bind(this);
        this.onChange = this.onChange.bind(this);
        this.state = {
            showModal: !!this.props.showAddService,
        };
    }

    onSubmit() {
        if (!this.state.name || this.state.name === '') {
            this.setState({
                errorMessage: 'Service name is required.',
            });
            return;
        }

        let keyValue = this.state.keyValue;

        if (keyValue && keyValue !== '') {
            keyValue = ServiceKeyUtils.y64Encode(
                ServiceKeyUtils.trimKey(keyValue)
            );
        }

        this.api
            .getService(this.props.domain, this.state.name)
            .then(() => {
                this.setState({
                    errorMessage:
                        'Service ' + this.state.name + ' already exists.',
                });
            })
            .catch((err) => {
                if (err.statusCode === 404) {
                    this.api
                        .addService(
                            this.props.domain,
                            this.state.name,
                            this.state.description,
                            this.state.providerEndpoint,
                            this.state.keyId,
                            keyValue,
                            this.props._csrf
                        )
                        .then(() => {
                            this.setState({ showModal: false });
                            this.props.onSubmit(`${this.state.name}`, false);
                        })
                        .catch((err) => {
                            this.setState({
                                errorMessage: RequestUtils.xhrErrorCheckHelper(
                                    err
                                ),
                            });
                        });
                } else {
                    this.setState({
                        errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                    });
                }
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
                title={`Add Service to ${this.props.domain}`}
                errorMessage={this.state.errorMessage}
                sections={
                    <AddServiceForm
                        api={this.api}
                        domain={this.props.domain}
                        onChange={this.onChange}
                        pageConfig={this.props.pageConfig}
                    />
                }
            />
        );
    }
}
