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
import Input from '../denali/Input';
import InputLabel from '../denali/InputLabel';
import styled from '@emotion/styled';
import { colors } from '../denali/styles';
import AddModal from '../modal/AddModal';
import RequestUtils from '../utils/RequestUtils';
import InputDropdown from '../denali/InputDropdown';
import { StaticWorkloadType } from '../constants/constants';
import RegexUtils from '../utils/RegexUtils';
import { addServiceHost } from '../../redux/thunks/services';
import { connect } from 'react-redux';

const SectionDiv = styled.div`
    align-items: center;
    display: flex;
    flex-flow: row nowrap;
    padding: 10px 10px;
`;

const StyledInputLabel = styled(InputLabel)`
    float: left;
    font-size: 14px;
    font-weight: 700;
    padding-top: 12px;
    width: 20%;
`;

const StyledInput = styled(Input)`
    width: 350px;
    padding: 0 12px !important;
`;

const StyledIncludedMembersDiv = styled.div`
    width: 65%;
`;

const SectionsDiv = styled.div`
    width: 780px;
    text-align: left;
    background-color: ${colors.white};
`;

class AddStaticInstances extends React.Component {
    constructor(props) {
        super(props);
        this.onSubmit = this.onSubmit.bind(this);
        this.resourceTypeChanged = this.resourceTypeChanged.bind(this);
        this.inputChanged = this.inputChanged.bind(this);
        this.state = {
            resourceValue: '',
            resourceType: '',
            pattern: '',
        };
    }

    resourceTypeChanged(chosen) {
        if (chosen && chosen.value != null) {
            this.setState({
                resourceType: chosen.value,
                pattern: chosen.pattern,
            });
        }
    }

    onSubmit() {
        this.setState({
            errorMessage: '',
        });

        //Input field validation

        if (!this.state.resourceType || this.state.resourceType === '') {
            this.setState({
                errorMessage: 'Resource Type is required.',
            });
            return;
        }

        if (!this.state.resourceValue || this.state.resourceValue === '') {
            this.setState({
                errorMessage: 'At least one resource value is required.',
            });
            return;
        }

        if (
            !RegexUtils.validate(this.state.resourceValue, this.state.pattern)
        ) {
            this.setState({
                errorMessage:
                    'Input validation failed, the allowed pattern is ' +
                    this.state.pattern,
            });
            return;
        }

        const auditRef = 'adding static ips for microsegmentation';
        let detail = {
            domainName: this.props.domain,
            serviceName: this.props.service,
            type: this.state.resourceType,
            name: this.state.resourceValue,
        };

        this.props
            .addServiceHost(
                this.props.domain,
                this.props.service,
                detail,
                auditRef,
                this.props._csrf
            )
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    inputChanged(evt) {
        this.setState({ resourceValue: evt.target.value });
    }
    render() {
        let sections = (
            <SectionsDiv>
                <SectionDiv>
                    <StyledInputLabel>Type and value:</StyledInputLabel>
                    <InputDropdown
                        name='resourceType'
                        defaultSelectedValue={this.state.resourceType}
                        options={StaticWorkloadType}
                        onChange={this.resourceTypeChanged}
                        placeholder='Select Resourcetype'
                        noclear
                        noanim
                        filterable
                    />
                    <StyledInput
                        placeholder='Enter value'
                        value={this.state.resourceValue}
                        onChange={this.inputChanged}
                        noanim
                        fluid
                    />
                </SectionDiv>
            </SectionsDiv>
        );
        return (
            <div data-testid='add-segment'>
                <AddModal
                    isOpen={this.props.showAddInstance}
                    cancel={this.props.onCancel}
                    submit={this.onSubmit}
                    title={`Add Static Instances`}
                    errorMessage={this.state.errorMessage}
                    sections={sections}
                />
            </div>
        );
    }
}

const mapDispatchToProps = (dispatch) => ({
    addServiceHost: (domainName, serviceName, details, auditRef, _csrf) =>
        dispatch(
            addServiceHost(domainName, serviceName, details, auditRef, _csrf)
        ),
});

export default connect(null, mapDispatchToProps)(AddStaticInstances);
