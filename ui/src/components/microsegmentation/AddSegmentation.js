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
import ButtonGroup from '../denali/ButtonGroup';
import Input from '../denali/Input';
import InputLabel from '../denali/InputLabel';
import Member from '../member/Member';
import styled from '@emotion/styled';
import { colors } from '../denali/styles';
import AddModal from '../modal/AddModal';
import RequestUtils from '../utils/RequestUtils';
import InputDropdown from '../denali/InputDropdown';
import Icon from '../denali/icons/Icon';
import {
    MICROSEGMENTATION_SERVICE_NAME_REGEX,
    MODAL_TIME_OUT,
    POLICY_ENFORCEMENT_REGEX,
    SEGMENTATION_CATEGORIES,
    SEGMENTATION_PROTOCOL,
} from '../constants/constants';
import NameUtils from '../utils/NameUtils';
import RadioButtonGroup from '../denali/RadioButtonGroup';
import CheckBox from '../denali/CheckBox';
import MicrosegmentationValidationModal from '../modal/MicrosegmentationValidationModal';
import RegexUtils from '../utils/RegexUtils';
import { selectServices } from '../../redux/selectors/services';
import {
    createOrUpdateTransportPolicy,
    validateMicrosegmentationPolicy,
} from '../../redux/thunks/microsegmentation';

import { connect } from 'react-redux';
import AppUtils from '../utils/AppUtils';

const SectionDiv = styled.div`
    align-items: flex-start;
    display: flex;
    flex-flow: row nowrap;
    padding: 10px 10px;
`;

const CheckBoxSectionDiv = styled.div`
    padding-top: 15px;
`;

const StyledInputLabel = styled(InputLabel)`
    float: left;
    font-size: 14px;
    font-weight: 700;
    padding-top: 12px;
    width: 20%;
`;

const StyledInputLabelHost = styled(InputLabel)`
    float: left;
    font-size: 14px;
    font-weight: 700;
    padding-top: 12px;
    width: 8%;
`;

const StyledButtonGroup = styled(ButtonGroup)`
    height: 40px;
    width: 200px;
`;

const StyledInput = styled(Input)`
    width: 750px;
    padding-top: 12px;
`;

const StyledInputHost = styled(Input)`
    width: 415px;
    padding-top: 12px;
`;

const AddCircleDiv = styled.div`
    margin-top: 5px;
    margin-left: 10px;
    padding-top: 12px;
`;

const RemoveCircleDiv = styled.div`
    margin-top: 5px;
    margin-left: 10px;
    padding-top: 12px;
`;

const ContentDiv = styled.div`
    flex: 1 1;
    margin-right: 1px;
`;

const ValidationErrorDiv = styled.div`
    flex: 1 1;
    margin-right: 1px;
    padding-top: 8px;
`;

const ValidationErrorStatusDiv = styled.div`
    flex: 1 1;
    margin-right: 1px;
    padding-top: 20px;
`;

const ValidationErrorSpan = styled.span`
    font: 300 16px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
`;

const AddMemberDiv = styled.div`
    display: flex;
`;

const StyledIncludedMembersDiv = styled.div`
    width: 65%;
`;

const SectionsDiv = styled.div`
    width: 1000px;
    text-align: left;
    background-color: ${colors.white};
`;

const StyledRadioButtonGroup = styled(RadioButtonGroup)`
    padding-top: 18px;
    width: 26%;
`;

const StyledInputDropdown = styled(InputDropdown)`
    padding-top: 12px;
`;

const StyledCheckBox = styled(CheckBox)``;

class AddSegmentation extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.categoryChanged = this.categoryChanged.bind(this);
        this.addMember = this.addMember.bind(this);
        this.onSubmit = this.onSubmit.bind(this);
        this.onEditSubmit = this.onEditSubmit.bind(this);
        this.loadServices = this.loadServices.bind(this);
        this.changeService = this.changeService.bind(this);
        this.protocolChanged = this.protocolChanged.bind(this);
        this.validatePort = this.validatePort.bind(this);
        this.inputChanged = this.inputChanged.bind(this);
        this.handleInputChange = this.handleInputChange.bind(this);
        this.handleAddClick = this.handleAddClick.bind(this);
        this.handleRemoveClick = this.handleRemoveClick.bind(this);
        this.editValidationPolicy = this.editValidationPolicy.bind(this);
        this.validateFields = this.validateFields.bind(this);
        this.validateServiceNames = this.validateServiceNames.bind(this);
        this.isScopeOnPrem = this.isScopeOnPrem.bind(this);
        this.scopeIsSet = this.scopeIsSet.bind(this);
        this.noSharedHostsBetweenModes =
            this.noSharedHostsBetweenModes.bind(this);
        this.getPolicyName = this.getPolicyName.bind(this);
        this.getRoleName = this.getRoleName.bind(this);
        this.hasChanges = this.hasChanges.bind(this);
        this.submit = this.submit.bind(this);

        let pesList = [
            {
                enforcementstate: 'report',
                instances: '',
                scopeonprem: 'true',
                scopeaws: 'false',
                scopegcp: 'false',
                scopeall: 'false',
                id: 1,
            },
        ];
        if (this.props.editMode && this.props.data['conditionsList']) {
            pesList = JSON.parse(
                JSON.stringify(this.props.data['conditionsList'])
            );
            for (var i = 0; i < pesList.length; i++) {
                // for backward compatatbility, policies without scope are assumed to be onprem
                if (
                    pesList[i].scopeonprem !== 'true' &&
                    pesList[i].scopeaws !== 'true' &&
                    pesList[i].scopegcp !== 'true' &&
                    pesList[i].scopeall !== 'true'
                ) {
                    pesList[i].scopeonprem = 'true';
                }
                // policyName is not needed and its structure is invalid for an assertionCondition value. So we'll remove it.
                delete pesList[i].policyName;
            }
        }

        this.state = {
            category: this.props.editMode
                ? this.props.data['category']
                : 'inbound',
            isCategory: this.props.editMode
                ? this.props.data['category'] === 'inbound'
                : true,
            inboundDestinationService:
                this.props.editMode && this.props.data['category'] === 'inbound'
                    ? this.props.data['destination_service']
                    : '',
            outboundSourceService:
                this.props.editMode &&
                this.props.data['category'] === 'outbound'
                    ? this.props.data['source_service']
                    : '',
            destinationPort: this.props.editMode
                ? this.props.data['destination_port']
                : '',
            sourceServiceMembers: '',
            destinationServiceMembers: '',
            sourcePort: this.props.editMode
                ? this.props.data['source_port']
                : '1024-65535',
            protocol: this.props.editMode ? this.props.data['layer'] : '',
            newMemberName: '',
            memberExpiry: '',
            memberReviewReminder: '',
            members: this.props.editMode
                ? this.props.data['category'] === 'inbound'
                    ? this.props.data['source_services'].map((str) => ({
                          memberName: str,
                          approved: true,
                      }))
                    : this.props.data['destination_services'].map((str) => ({
                          memberName: str,
                          approved: true,
                      }))
                : [],
            protocolValid: true,
            action: '',
            resource: '',
            destinationServiceList: [],
            identifier: this.props.editMode
                ? this.props.data['identifier']
                : '',
            justification: '',
            PESList: pesList,
            data: props.data,
            validationCheckbox: false,
            saving: 'todo',
            validationError: 'none',
            validationStatus: 'valid',
            radioButtonInputs: [
                {
                    label: 'Report (on prem only)',
                    value: 'report',
                    disabled: false,
                },
                {
                    label: 'Enforce',
                    value: 'enforce',
                    disabled: false,
                },
            ],
        };
    }

    componentDidMount() {
        this.loadServices();
    }

    categoryChanged(button) {
        if (!this.props.editMode) {
            this.setState({
                category: button.name,
                isCategory: !this.state.isCategory, //Setting isCategory true for inbound and false for outbound through out the code
                errorMessage: '',
                saving: 'todo',
            });
        }
    }

    protocolChanged(chosen) {
        if (chosen && chosen.value != null) {
            this.setState({
                protocol: chosen.value,
                protocolValid: true,
            });
        } else {
            this.setState({
                protocolValid: false,
            });
        }
    }

    inputChanged(evt, key) {
        let value = '';

        if (key === 'validationCheckbox') {
            value = evt.target.checked;
        } else if (evt.target) {
            value = evt.target.value;
        } else {
            value = evt ? evt : '';
        }
        this.setState({
            [key]: value,
        });
    }

    editValidationPolicy() {
        this.setState({
            validationStatus: '',
            validationError: 'none',
        });
    }

    noSharedHostsBetweenModes(pesList) {
        if (pesList.length <= 1) {
            return true;
        }

        const firstConditionInstances = pesList[0].instances.split(',');
        const secondConditionInstances = pesList[1].instances.split(',');
        if (
            firstConditionInstances.length <= 0 ||
            secondConditionInstances.length <= 0
        ) {
            // If one condition doesn't have any hosts - no risk of common hosts
            return true;
        }
        if (
            firstConditionInstances.includes('*') ||
            firstConditionInstances.includes('') ||
            secondConditionInstances.includes('*') ||
            secondConditionInstances.includes('')
        ) {
            // If one condition has the wild card, any host listed on the second condition will be shared with it.
            return false;
        }

        const sharedInstances = firstConditionInstances.filter((value) =>
            secondConditionInstances.includes(value)
        );
        return sharedInstances.length == 0;
    }

    scopeIsSet(pesList) {
        for (var i = 0; i < pesList.length; i++) {
            if (
                pesList[i].scopeonprem != 'true' &&
                pesList[i].scopeaws != 'true' &&
                pesList[i].scopegcp !== 'true' &&
                pesList[i].scopeall != 'true'
            ) {
                return false;
            }
        }
        return true;
    }

    addMember() {
        let sourceServiceName = this.state.isCategory
            ? this.state.sourceServiceMembers
            : this.state.destinationServiceMembers;
        let members = this.state.members;

        if (!sourceServiceName) {
            return;
        }
        let names = NameUtils.splitNames(sourceServiceName);
        for (let i = 0; i < names.length; i++) {
            members.push({
                memberName: names[i],
            });
        }

        if (this.state.isCategory) {
            this.setState({
                sourceServiceMembers: '',
            });
        } else {
            this.setState({
                destinationServiceMembers: '',
            });
        }
        this.setState({
            members,
        });
    }

    deleteMember(idx) {
        let members = this.state.members;
        // this if is done to avoid [null] condition
        if (members.length === 1) {
            members = [];
        } else {
            members.splice(idx, 1);
        }
        this.setState({ members });
    }

    createOrUpdateTransportPolicy(data, roleName, policyName) {}

    validatePort(port) {
        var regex = new RegExp('^[0-9-,]*$');
        var result = {
            error: 0,
            port: port,
        };

        if (!regex.test(port)) {
            this.setState({
                errorMessage: "Port can only contain numbers, '-' and ','",
                saving: 'todo',
            });
            result.error = 1;
            return result;
        }

        let ports = port.split(',');
        for (var i = 0; i < ports.length; i++) {
            if (ports[i].indexOf('-') != -1) {
                let range = ports[i].split('-');
                let start = parseInt(range[0]);
                let end = parseInt(range[1]);
                if (
                    range.length != 2 ||
                    isNaN(start) ||
                    isNaN(end) ||
                    start < 1 ||
                    end < 1 ||
                    start > end ||
                    start > 65535 ||
                    end > 65535
                ) {
                    this.setState({
                        errorMessage:
                            'Invalid port: ' +
                            ports[i] +
                            '. Valid range of port numbers: 1-65535',
                        saving: 'todo',
                    });
                    result.error = 1;
                    return result;
                }
            } else if (ports[i] < 0 && ports[i] > 65535) {
                this.setState({
                    errorMessage:
                        'Invalid port: ' +
                        ports[i] +
                        'Valid range of port numbers: 1-65535',
                    saving: 'todo',
                });
                result.error = 1;
                return result;
            } else {
                ports[i] = ports[i] + '-' + ports[i];
            }
        }

        result.port = ports.join(',');
        return result;
    }

    validateEnforcementPolicy(PesList) {
        for (const policy of PesList) {
            if (
                !RegexUtils.validate(policy.instances, POLICY_ENFORCEMENT_REGEX)
            ) {
                return false;
            }
        }

        return true;
    }

    validateServiceNames(inputServiceMembers, existingMembers) {
        // if both lists are empty - return true as invalid, because at least one service must be provided
        if (
            (!Array.isArray(inputServiceMembers) ||
                inputServiceMembers.length === 0) &&
            (!Array.isArray(existingMembers) || existingMembers.length === 0)
        )
            return true;

        const validateMembers = (membersList) => {
            membersList.forEach((serviceMember) => {
                let memberName = serviceMember.memberName
                    ? serviceMember.memberName
                    : serviceMember;
                if (
                    !RegexUtils.validate(
                        memberName,
                        MICROSEGMENTATION_SERVICE_NAME_REGEX
                    )
                ) {
                    // invalid service name
                    return true;
                }
            });
            return false;
        };

        return (
            validateMembers(inputServiceMembers) ||
            validateMembers(existingMembers)
        );
    }

    // isScopeOnPrem returns true if onprem is a selected option
    isScopeOnPrem() {
        for (let i = 0; i < this.state.PESList.length; i++) {
            if (this.state.PESList[i].scopeonprem == 'false') {
                return false;
            }
        }
        return true;
    }

    validateFields() {
        const isBlank = (val) => !val || val.trim() === '';
        if (this.state.isCategory) {
            if (isBlank(this.state.inboundDestinationService)) {
                this.setState({
                    errorMessage: 'Destination service is required.',
                    saving: 'todo',
                });
                return 1;
            }

            if (!this.validateEnforcementPolicy(this.state.PESList)) {
                this.setState({
                    errorMessage: 'Invalid policy enforcement hosts',
                    saving: 'todo',
                });

                return 1;
            }

            if (isBlank(this.state.destinationPort)) {
                this.setState({
                    errorMessage: 'Destination Port is required.',
                    saving: 'todo',
                });
                return 1;
            }

            if (
                this.validateServiceNames(
                    NameUtils.splitNames(this.state.sourceServiceMembers),
                    this.state.members
                )
            ) {
                this.setState({
                    errorMessage: 'Invalid source service',
                    saving: 'todo',
                });
                return 1;
            }

            if (isBlank(this.state.sourcePort)) {
                this.setState({
                    errorMessage: 'Source port is required.',
                    saving: 'todo',
                });
                return 1;
            }

            if (isBlank(this.state.protocol)) {
                this.setState({
                    errorMessage: 'Protocol is required.',
                    saving: 'todo',
                });
                return 1;
            }
        } else {
            if (isBlank(this.state.outboundSourceService)) {
                this.setState({
                    errorMessage: 'Source service is required.',
                    saving: 'todo',
                });
                return 1;
            }

            if (isBlank(this.state.sourcePort)) {
                this.setState({
                    errorMessage: 'Source port is required.',
                    saving: 'todo',
                });
                return 1;
            }

            if (
                this.validateServiceNames(
                    NameUtils.splitNames(this.state.destinationServiceMembers),
                    this.state.members
                )
            ) {
                this.setState({
                    errorMessage: 'Invalid destination service.',
                    saving: 'todo',
                });
                return 1;
            }

            if (isBlank(this.state.destinationPort)) {
                this.setState({
                    errorMessage: 'Destination Port is required.',
                    saving: 'todo',
                });
                return 1;
            }

            if (isBlank(this.state.protocol)) {
                this.setState({
                    errorMessage: 'Protocol is required.',
                    saving: 'todo',
                });
                return 1;
            }
        }

        if (
            this.props.justificationRequired &&
            isBlank(this.state.justification)
        ) {
            this.setState({
                errorMessage: 'Justification is required to add a member.',
                saving: 'todo',
            });
            return 1;
        }

        if (!this.scopeIsSet(this.state.PESList)) {
            this.setState({
                errorMessage: 'Please select at least one scope.',
                saving: 'todo',
            });
            return 1;
        }

        if (!this.noSharedHostsBetweenModes(this.state.PESList)) {
            this.setState({
                errorMessage:
                    'The same host can not exist in both "Report" and "Enforce" modes.',
                saving: 'todo',
            });
            return 1;
        }

        if (isBlank(this.state.identifier)) {
            this.setState({
                errorMessage: 'Identifier is required.',
                saving: 'todo',
            });
            return 1;
        }
        return 0;
    }

    getPolicyName() {
        if (this.state.isCategory) {
            return (
                'acl.' +
                this.state.inboundDestinationService +
                '.' +
                SEGMENTATION_CATEGORIES[0].name
            );
        } else {
            return (
                'acl.' +
                this.state.outboundSourceService +
                '.' +
                SEGMENTATION_CATEGORIES[1].name
            );
        }
    }

    getRoleName() {
        if (this.state.isCategory) {
            return (
                'acl.' +
                this.state.inboundDestinationService +
                '.' +
                SEGMENTATION_CATEGORIES[0].name +
                '-' +
                this.state.identifier
            );
        } else {
            return (
                'acl.' +
                this.state.outboundSourceService +
                '.' +
                SEGMENTATION_CATEGORIES[1].name +
                '-' +
                this.state.identifier
            );
        }
    }

    async onEditSubmit(evt, skipValidation = false) {
        this.setState({
            saving: 'saving',
        });
        if (this.validateFields()) {
            return;
        }
        // add all members to one list
        this.addMember();

        // if no changes - return
        if (!this.hasChanges()) {
            // if no changes - return
            this.setState({
                errorMessage: 'No changes to save.',
                saving: 'todo',
            });
            return;
        }

        await this.submit(skipValidation);
    }

    async onSubmit(evt, skipValidation = false) {
        this.setState({
            saving: 'saving',
        });
        if (this.validateFields()) {
            return;
        }
        // add all members to one list
        this.addMember();

        await this.submit(skipValidation);
    }

    async submit(skipValidation = false) {
        let source = this.validatePort(this.state.sourcePort);
        let destination = this.validatePort(this.state.destinationPort);

        if (source.error || destination.error) {
            return;
        }

        const members =
            this.state.members.filter((member) => {
                return (
                    member.memberName != null || member.memberName != undefined
                );
            }) || [];

        let assertionId = this.state?.data?.assertionIdx || -1;

        try {
            if (this.state.validationCheckbox === true && !skipValidation) {
                const result = await this.props.validateMicrosegmentationPolicy(
                    this.state.category,
                    members,
                    this.state.inboundDestinationService,
                    this.state.outboundSourceService,
                    source.port,
                    destination.port,
                    this.state.protocol,
                    this.props.domain,
                    assertionId,
                    this.props._csrf
                );
                if (result.status !== 'VALID') {
                    this.setState({
                        validationError: result.errors.join('\r\n'),
                        validationStatus: result.status,
                        saving: 'todo',
                    });
                }
            }
        } catch (err) {
            this.setState({
                errorMessage: RequestUtils.fetcherErrorCheckHelper(err),
                saving: 'todo',
                validationError: 'none',
            });
            return;
        }

        try {
            const data = {
                identifier: this.state.identifier,
                category: this.state.category,
                domain: this.props.domain,
                service: this.state.isCategory
                    ? this.state.inboundDestinationService
                    : this.state.outboundSourceService,
                peers: members,
                pesList: this.state.PESList, // conditions
                sourcePort: source.port,
                destinationPort: destination.port,
                protocol: this.state.protocol,
            };
            await this.props.createOrUpdateTransportPolicy(
                this.props.domain,
                data,
                this.props._csrf,
                this.getRoleName(),
                this.getPolicyName()
            );
            this.props.onSubmit();
        } catch (err) {
            this.props.showError(RequestUtils.fetcherErrorCheckHelper(err));
        }
    }

    hasChanges() {
        let originalMembers = [];
        if (this.props.data['category'] === 'inbound') {
            originalMembers = this.props.data['source_services'];
        } else {
            originalMembers = this.props.data['destination_services'];
        }

        let originalMembersHash = originalMembers.reduce(function (map, obj) {
            map[obj] = 1;
            return map;
        }, {});

        for (let member of this.state.members) {
            if (!originalMembersHash[member.memberName]) {
                return true;
            }
        }
        if (
            this.state.members.length !==
            Object.keys(originalMembersHash).length
        ) {
            return true;
        }

        if (
            this.props.data['destination_port'] !==
                this.state.destinationPort ||
            this.props.data['source_port'] !== this.state.sourcePort ||
            this.props.data['layer'] !== this.state.protocol
        ) {
            return true;
        }

        const comparer = (otherArray) => (current) =>
            otherArray.filter(
                (other) =>
                    other.instances == current.instances &&
                    other.enforcementstate == current.enforcementstate &&
                    other.scopeall == current.scopeall &&
                    other.scopeonprem == current.scopeonprem &&
                    other.scopeaws == current.scopeaws &&
                    other.scopegcp == current.scopegcp &&
                    other.id == current.id
            ).length == 0;

        if (this.props.data['conditionsList']) {
            let x = this.props.data['conditionsList'].filter(
                comparer(this.state.PESList)
            );
            let y = this.state.PESList.filter(
                comparer(this.props.data['conditionsList'])
            );

            if (x.length != 0 || y.length != 0) {
                return true;
            }
        } else {
            return true;
        }

        return false;
    }

    loadServices() {
        const services = AppUtils.deepClone(this.props.services);
        for (let i = 0; i < services.length; i++) {
            let name = NameUtils.getShortName('.', services[i]['name']);
            services[i]['name'] = name;
            services[i]['value'] = name;
            delete services[i]['modified'];
        }
        this.setState({
            destinationServiceList: services,
        });
        setTimeout(
            () =>
                this.setState({
                    showSuccess: false,
                }),
            MODAL_TIME_OUT
        );
    }

    changeService(chosen, key) {
        if (chosen && chosen.name != null) {
            const name = chosen.name;
            this.setState({
                [key]: name,
            });
        }
    }

    toggleDisableRadioButton(checked, list, index, inputs) {
        if (checked) {
            list[index]['enforcementstate'] = 'enforce';
            inputs[0].disabled = true; // disable report mode when scope aws
        } else {
            inputs[0].disabled = false;
        }
    }

    handleInputChange(e, index) {
        const { name, value, checked } = e.target;
        const list = [...this.state.PESList];
        const checkedStr = checked ? 'true' : 'false';
        let inputs = [...this.state.radioButtonInputs];
        if (name.includes('enforcementStateRadioButton')) {
            list[index]['enforcementstate'] = value;
            if (list.length == 2) {
                if (value === 'report') {
                    list[1]['enforcementstate'] = 'enforce';
                } else {
                    list[1]['enforcementstate'] = 'report';
                }
            }
        } else if (name.includes('instances')) {
            list[index]['instances'] = value;
        } else if (name.includes('scopeall')) {
            list[index]['scopeall'] = checkedStr;
            list[index]['scopeaws'] = 'false';
            list[index]['scopegcp'] = 'false';
            list[index]['scopeonprem'] = 'false';
            this.toggleDisableRadioButton(checked, list, index, inputs);
        } else if (name.includes('scopeonprem')) {
            list[index]['scopeonprem'] = checkedStr;
        } else if (name.includes('scopeaws')) {
            list[index]['scopeaws'] = checkedStr;
            this.toggleDisableRadioButton(checked, list, index, inputs);
        } else if (name.includes('scopegcp')) {
            list[index]['scopegcp'] = checkedStr;
            this.toggleDisableRadioButton(checked, list, index, inputs);
        }
        this.setState({
            PESList: list,
            radioButtonInputs: inputs,
        });
    }

    handleAddClick() {
        let enforcementstate = 'report';
        if (this.state.PESList[0]['enforcementstate'] === 'report') {
            enforcementstate = 'enforce';
        }
        this.setState({
            PESList: [
                ...this.state.PESList,
                {
                    enforcementstate: enforcementstate,
                    instances: '',
                    id: 2,
                    scopeonprem: 'true',
                    scopeaws: 'false',
                    scopeall: 'false',
                    scopegcp: 'false',
                },
            ],
        });
    }

    handleRemoveClick(index) {
        const list = [...this.state.PESList];
        list.splice(index, 1);
        list[0]['id'] = 1;
        this.setState({
            PESList: list,
        });
    }

    render() {
        let members = this.state.members
            ? this.state.members.map((item, idx) => {
                  // dummy place holder so that it can be be used in the form
                  const newItem = { ...item };
                  newItem.approved = true;
                  let remove = this.deleteMember.bind(this, idx);
                  return (
                      <Member
                          key={idx}
                          item={newItem}
                          onClickRemove={remove}
                          noanim
                      />
                  );
              })
            : '';

        let sections = (
            <SectionsDiv>
                <SectionDiv>
                    <StyledInputLabel>ACL Category</StyledInputLabel>
                    <StyledButtonGroup
                        buttons={SEGMENTATION_CATEGORIES}
                        selectedName={
                            this.props.data
                                ? this.state.data['category']
                                : this.state.category
                        }
                        onClick={this.categoryChanged}
                        noanim
                    />
                </SectionDiv>
                <SectionDiv>
                    <StyledInputLabel>Identifier</StyledInputLabel>
                    <StyledInput
                        data-wdio='identifier'
                        placeholder='Enter a unique identifier for this ACL policy'
                        value={this.state.identifier}
                        onChange={(event) =>
                            this.inputChanged(event, 'identifier')
                        }
                        noanim
                        fluid
                        disabled={this.props.editMode}
                    />
                </SectionDiv>
                <SectionDiv>
                    <StyledInputLabel>
                        {this.state.isCategory
                            ? 'Destination Service'
                            : 'Source Service'}
                    </StyledInputLabel>
                    <StyledInputDropdown
                        name='destinationService'
                        options={this.state.destinationServiceList}
                        value={
                            this.props.editMode
                                ? this.state.isCategory
                                    ? this.state.inboundDestinationService
                                    : this.state.outboundSourceService
                                : undefined
                        }
                        onChange={(item) =>
                            this.changeService(
                                item,
                                this.state.isCategory
                                    ? 'inboundDestinationService'
                                    : 'outboundSourceService'
                            )
                        }
                        placeholder={
                            this.state.isCategory
                                ? 'Select Destination Service'
                                : 'Select Source Service'
                        }
                        noanim
                        filterable
                        disabled={this.props.editMode}
                    />
                </SectionDiv>
                {this.state.PESList.map((x, i) => {
                    return (
                        <div>
                            <SectionDiv>
                                <StyledInputLabel>Scope</StyledInputLabel>
                                <CheckBoxSectionDiv>
                                    <StyledCheckBox
                                        checked={x.scopeall === 'true'}
                                        name={'scopeallCheckBox' + i}
                                        id={'scopeallCheckBox' + i}
                                        key={'scopeallCheckBox' + i}
                                        label='All'
                                        onChange={(e) =>
                                            this.handleInputChange(e, i)
                                        }
                                    />
                                    <StyledCheckBox
                                        checked={x.scopeonprem === 'true'}
                                        disabled={x.scopeall === 'true'}
                                        name={'scopeonpremCheckBox' + i}
                                        id={'scopeonpremCheckBox' + i}
                                        key={'scopeonpremCheckBox' + i}
                                        label='On-Prem'
                                        onChange={(e) =>
                                            this.handleInputChange(e, i)
                                        }
                                    />
                                    <StyledCheckBox
                                        checked={x.scopeaws === 'true'}
                                        disabled={x.scopeall === 'true'}
                                        name={'scopeawsCheckBox' + i}
                                        id={'scopeawsCheckBox' + i}
                                        key={'scopeawsCheckBox' + i}
                                        label='AWS'
                                        onChange={(e) =>
                                            this.handleInputChange(e, i)
                                        }
                                    />
                                    <StyledCheckBox
                                        checked={x.scopegcp === 'true'}
                                        disabled={x.scopeall === 'true'}
                                        name={'scopegcpCheckBox' + i}
                                        id={'scopegcpCheckBox' + i}
                                        key={'scopegcpCheckBox' + i}
                                        label='GCP'
                                        onChange={(e) =>
                                            this.handleInputChange(e, i)
                                        }
                                    />
                                </CheckBoxSectionDiv>
                            </SectionDiv>
                            <SectionDiv>
                                <StyledInputLabel>
                                    Policy Enforcement State
                                </StyledInputLabel>
                                <StyledRadioButtonGroup
                                    name={'enforcementStateRadioButton' + i}
                                    inputs={this.state.radioButtonInputs}
                                    selectedValue={x.enforcementstate?.toLowerCase()}
                                    onChange={(e) =>
                                        this.handleInputChange(e, i)
                                    }
                                    disabled={i == 1 ? true : undefined}
                                />
                                <StyledInputLabelHost>
                                    Hosts
                                </StyledInputLabelHost>
                                <StyledInputHost
                                    placeholder='Comma separated list, Leave blank to apply to all hosts'
                                    value={x.instances}
                                    name={'instances' + i}
                                    data-wdio={'instances' + i}
                                    onChange={(e) =>
                                        this.handleInputChange(e, i)
                                    }
                                    noanim
                                    error={x.instances.length > 2048}
                                    message={
                                        x.instances.length > 2048
                                            ? 'Limit is 2048 characters. Contact #athenz channel on slack'
                                            : ''
                                    }
                                    fluid
                                />
                                {this.state.PESList.length < 2 ? (
                                    <AddCircleDiv>
                                        <Icon
                                            icon={'add-circle'}
                                            dataWdio={'add-circle'}
                                            isLink
                                            color={colors.icons}
                                            size='1.75em'
                                            onClick={this.handleAddClick}
                                        />
                                    </AddCircleDiv>
                                ) : (
                                    <RemoveCircleDiv>
                                        <Icon
                                            icon={'minus'}
                                            isLink
                                            color={colors.icons}
                                            size='1.75em'
                                            onClick={() =>
                                                this.handleRemoveClick(i)
                                            }
                                        />
                                    </RemoveCircleDiv>
                                )}
                            </SectionDiv>
                        </div>
                    );
                })}

                <SectionDiv>
                    <StyledInputLabel>
                        {this.state.isCategory
                            ? 'Destination Port(s)'
                            : 'Source Port(s)'}
                    </StyledInputLabel>
                    <ContentDiv>
                        <StyledInput
                            data-wdio='destination-port'
                            placeholder='eg: 4443'
                            value={
                                this.state.isCategory
                                    ? this.state.destinationPort
                                    : this.state.sourcePort
                            }
                            onChange={(event) =>
                                this.inputChanged(
                                    event,
                                    this.state.isCategory
                                        ? 'destinationPort'
                                        : 'sourcePort'
                                )
                            }
                            noanim
                            fluid
                            disabled={this.props.editMode}
                        />
                    </ContentDiv>
                </SectionDiv>
                <SectionDiv>
                    <StyledInputLabel>
                        {this.state.isCategory
                            ? 'Source Service'
                            : 'Destination Service'}
                    </StyledInputLabel>
                    <StyledInput
                        data-wdio='source-service'
                        placeholder='eg: yamas.api, sys.auth.zms'
                        value={
                            this.state.isCategory
                                ? this.state.sourceServiceMembers
                                : this.state.destinationServiceMembers
                        }
                        onChange={(event) =>
                            this.inputChanged(
                                event,
                                this.state.isCategory
                                    ? 'sourceServiceMembers'
                                    : 'destinationServiceMembers'
                            )
                        }
                        noanim
                        fluid
                    />
                </SectionDiv>
                <SectionDiv>
                    <StyledInputLabel />
                    <StyledIncludedMembersDiv>
                        {members}
                    </StyledIncludedMembersDiv>
                </SectionDiv>
                <SectionDiv>
                    <StyledInputLabel>
                        {this.state.isCategory
                            ? 'Source Port(s)'
                            : 'Destination Port(s)'}
                    </StyledInputLabel>
                    <ContentDiv>
                        <AddMemberDiv>
                            <StyledInput
                                placeholder='eg: 1024-65535'
                                value={
                                    this.state.isCategory
                                        ? this.state.sourcePort
                                        : this.state.destinationPort
                                }
                                onChange={(event) =>
                                    this.inputChanged(
                                        event,
                                        this.state.isCategory
                                            ? 'sourcePort'
                                            : 'destinationPort'
                                    )
                                }
                                noanim
                                fluid
                                disabled={this.props.editMode}
                            />
                        </AddMemberDiv>
                    </ContentDiv>
                </SectionDiv>
                <SectionDiv>
                    <StyledInputLabel>Protocol</StyledInputLabel>
                    <StyledInputDropdown
                        name='protocol'
                        defaultSelectedValue={this.state.protocol}
                        options={SEGMENTATION_PROTOCOL}
                        onChange={this.protocolChanged}
                        placeholder='Select Protocol'
                        noanim
                        filterable
                        disabled={this.props.editMode}
                    />
                </SectionDiv>
                {this.props.pageFeatureFlag['policyValidation'] && (
                    <SectionDiv>
                        <StyledInputLabel>Validation</StyledInputLabel>
                        <CheckBoxSectionDiv>
                            <StyledCheckBox
                                disabled={!this.isScopeOnPrem()}
                                checked={this.state.validationCheckbox}
                                name={
                                    'checkbox-validate-policy' +
                                    this.state.isCategory
                                }
                                id={
                                    'checkbox-validate-policy' +
                                    this.state.isCategory
                                }
                                key={
                                    'checkbox-validate-policy' +
                                    this.state.isCategory
                                }
                                label='Validate Microsegmentation policy against PES network policy (only for onprem hosts)'
                                onChange={(event) =>
                                    this.inputChanged(
                                        event,
                                        'validationCheckbox'
                                    )
                                }
                            />
                        </CheckBoxSectionDiv>
                    </SectionDiv>
                )}
                {this.props.justificationRequired && (
                    <SectionDiv>
                        <StyledInputLabel>Justification</StyledInputLabel>
                        <ContentDiv>
                            <StyledInput
                                value={this.state.justification}
                                onChange={(event) =>
                                    this.inputChanged(event, 'justification')
                                }
                                placeholder='Enter justification here'
                            />
                        </ContentDiv>
                    </SectionDiv>
                )}
            </SectionsDiv>
        );

        let validationResponseSections = (
            <SectionsDiv>
                <SectionDiv>
                    <StyledInputLabel>Status</StyledInputLabel>
                    <ValidationErrorStatusDiv>
                        {this.state.validationStatus}
                    </ValidationErrorStatusDiv>
                </SectionDiv>
                <SectionDiv>
                    <StyledInputLabel>Errors</StyledInputLabel>
                    <ValidationErrorDiv>
                        <pre>
                            <ValidationErrorSpan>
                                {this.state.validationError}
                            </ValidationErrorSpan>
                        </pre>
                    </ValidationErrorDiv>
                </SectionDiv>
            </SectionsDiv>
        );

        return (
            <div data-testid='add-segment'>
                {this.state.validationError === 'none' && (
                    <AddModal
                        isOpen={this.props.showAddSegment}
                        cancel={this.props.onCancel}
                        submit={
                            this.props.editMode
                                ? this.onEditSubmit
                                : this.onSubmit
                        }
                        title={
                            this.props.editMode
                                ? `Edit Microsegmentation ACL Policy`
                                : `Add Microsegmentation ACL Policy`
                        }
                        errorMessage={this.state.errorMessage}
                        saving={this.state.saving}
                        sections={sections}
                        width={'1050px'}
                        bodyMaxHeight={'90%'}
                        modalHeight={'85vh'}
                    />
                )}
                {this.state.validationError !== 'none' && (
                    <MicrosegmentationValidationModal
                        isOpen={this.props.showAddSegment}
                        editPolicy={this.editValidationPolicy}
                        submit={
                            this.props.editMode
                                ? this.onEditSubmit
                                : this.onSubmit
                        }
                        title={`Validation Errors`}
                        editMode={this.props.editMode}
                        saving={this.state.saving}
                        sections={validationResponseSections}
                        width={'1050px'}
                        bodyHeight={'90%'}
                        modalHeight={'85vh'}
                    />
                )}
            </div>
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
    validateMicrosegmentationPolicy: (
        category,
        roleMembers,
        inboundDestinationService,
        outboundSourceService,
        sourcePort,
        destinationPort,
        protocol,
        domainName,
        assertionId,
        _csrf
    ) =>
        dispatch(
            validateMicrosegmentationPolicy(
                category,
                roleMembers,
                inboundDestinationService,
                outboundSourceService,
                sourcePort,
                destinationPort,
                protocol,
                domainName,
                assertionId,
                _csrf
            )
        ),
    createOrUpdateTransportPolicy: (
        domainName,
        data,
        _csrf,
        roleName,
        policyName
    ) =>
        dispatch(
            createOrUpdateTransportPolicy(
                domainName,
                data,
                _csrf,
                roleName,
                policyName
            )
        ),
});

export default connect(mapStateToProps, mapDispatchToProps)(AddSegmentation);
