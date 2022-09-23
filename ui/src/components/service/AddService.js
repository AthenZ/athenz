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
import AddServiceForm from './AddServiceForm';
import ServiceKeyUtils from '../utils/ServiceKeyUtils';
import RequestUtils from '../utils/RequestUtils';
import { connect } from 'react-redux';
import { addService } from '../../redux/thunks/services';
import { selectServices } from '../../redux/selectors/services';

class AddService extends React.Component {
    constructor(props) {
        super(props);
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
        let service = {
            name: this.state.name,
            description: this.state.description,
            providerEndpoint: this.state.providerEndpoint,
            keyId: this.state.keyId,
            keyValue,
        };
        this.props
            .addService(this.props.domain, service, this.props._csrf)
            .then(() => {
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
                title={`Add Service to ${this.props.domain}`}
                errorMessage={this.state.errorMessage}
                sections={
                    <AddServiceForm
                        domain={this.props.domain}
                        onChange={this.onChange}
                        pageConfig={this.props.pageConfig}
                    />
                }
            />
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        services: selectServices(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    addService: (domainName, service, _csrf) =>
        dispatch(addService(domainName, service, _csrf)),
});

export default connect(mapStateToProps, mapDispatchToProps)(AddService);
