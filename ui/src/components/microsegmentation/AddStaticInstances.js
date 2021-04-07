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
import Member from '../member/Member';
import styled from '@emotion/styled';
import { colors } from '../denali/styles';
import AddModal from '../modal/AddModal';
import RequestUtils from '../utils/RequestUtils';
import InputDropdown from '../denali/InputDropdown';
import Icon from '../denali/icons/Icon';
import { STATIC_INSTANCES_RESOURCE_TYPES } from '../constants/constants';
import NameUtils from '../utils/NameUtils';

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
    padding: 0 12px;
`;

const AddCircleDiv = styled.div`
    margin-top: 5px;
    margin-left: 5px;
`;

const StyledIncludedMembersDiv = styled.div`
    width: 65%;
`;

const SectionsDiv = styled.div`
    width: 780px;
    text-align: left;
    background-color: ${colors.white};
`;

export default class AddStaticInstances extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.addMember = this.addMember.bind(this);
        this.onSubmit = this.onSubmit.bind(this);
        this.resourceTypeChanged = this.resourceTypeChanged.bind(this);
        this.inputChanged = this.inputChanged.bind(this);
        this.state = {
            members: [],
            resourceValue: '',
        };
    }

    resourceTypeChanged(chosen) {
        if (chosen && chosen.value != null) {
            this.setState({
                resourceType: chosen.value,
            });
        }
    }

    addMember() {
        let resourceVal = this.state.resourceValue;
        let members = this.state.members;

        if (!resourceVal) {
            return;
        }
        let names = NameUtils.splitNames(resourceVal);

        for (let i = 0; i < names.length; i++) {
            members.push({
                memberName: names[i],
            });
        }
        this.setState({
            members,
            resourceValue: '',
        });
    }

    deleteMember(idx) {
        let members = this.state.members;
        // this if is done to avoid [null] condition
        if (members.length === 1) {
            members = [];
        } else {
            delete members[idx];
        }
        this.setState({ members });
    }

    onSubmit() {
        this.setState({
            errorMessage: '',
        });

        this.addMember();

        //Input field validation

        if (!this.state.resourceType || this.state.resourceType === '') {
            this.setState({
                errorMessage: 'Resource Type is required.',
            });
            return;
        }

        if (this.state.members <= 0) {
            this.setState({
                errorMessage: 'Atlease one resource value is required.',
            });
            return;
        }

        var urlParts = window.location.pathname.split('/');
        var serviceName = this.props.service;
        var fullServiceName = this.props.domain + '.' + serviceName;
        var auditRef = 'adding static ips for micro-segment';
        var hostDetails = [];
        let detail = { name: fullServiceName };
        this.state.members.forEach((member) => {
            hostDetails.push(member.memberName);
        });
        this.api
            .getServiceHost(this.props.domain, serviceName)
            .then((data) => {
                if (!data.hosts) {
                    detail.hosts = hostDetails;
                } else {
                    detail.hosts = [
                        ...new Set([...hostDetails, ...data.hosts]),
                    ];
                }
                this.api
                    .addServiceHost(
                        this.props.domain,
                        serviceName,
                        detail,
                        auditRef,
                        this.props._csrf
                    )
                    .then(() => {
                        if (!this.state.errorMessage) {
                            this.props.onSubmit();
                        }
                    })
                    .catch((err) => {
                        this.setState({
                            errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                        });
                    });
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    inputChanged(key, evt) {
        let value = '';
        if (evt.target) {
            value = evt.target.value;
        } else {
            value = evt ? evt : '';
        }
        this.setState({ [key]: value });
    }
    render() {
        let typeChanged = this.inputChanged.bind(this, 'resourceValue');
        let members = this.state.members
            ? this.state.members.map((item, idx) => {
                  // dummy place holder so that it can be be used in the form
                  item.approved = true;
                  let remove = this.deleteMember.bind(this, idx);
                  return (
                      <Member
                          key={idx}
                          item={item}
                          onClickRemove={remove}
                          noanim
                      />
                  );
              })
            : '';
        let sections = (
            <SectionsDiv>
                <SectionDiv>
                    <StyledInputLabel>Type and value:</StyledInputLabel>
                    <InputDropdown
                        name='resourceType'
                        defaultSelectedValue={this.state.resourceType}
                        options={STATIC_INSTANCES_RESOURCE_TYPES}
                        onChange={this.resourceTypeChanged}
                        placeholder='Select Resourcetype'
                        noclear
                        noanim
                        filterable
                    />

                    <StyledInput
                        placeholder='Enter value'
                        value={this.state.resourceValue}
                        onChange={typeChanged}
                        noanim
                        fluid
                    />
                    <AddCircleDiv>
                        <Icon
                            icon={'add-circle'}
                            isLink
                            color={colors.icons}
                            size='1.75em'
                            onClick={this.addMember}
                        />
                    </AddCircleDiv>
                </SectionDiv>
                <SectionDiv>
                    <StyledInputLabel />
                    <StyledIncludedMembersDiv>
                        {members}
                    </StyledIncludedMembersDiv>
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
