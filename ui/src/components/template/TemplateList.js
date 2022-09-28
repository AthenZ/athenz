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
import { colors } from '../denali/styles';
import TemplateRow from './TemplateRow';
import Alert from '../denali/Alert';
import { MODAL_TIME_OUT } from '../constants/constants';
import { connect } from 'react-redux';

import RequestUtils from '../utils/RequestUtils';
import { makeRolesExpires } from '../../redux/actions/roles';
import { makePoliciesExpires } from '../../redux/actions/policies';
import { selectIsLoading } from '../../redux/selectors/loading';
import { ReduxPageLoader } from '../denali/ReduxPageLoader';

const TemplatesSectionDiv = styled.div`
    margin: 20px;
`;

const TemplateTable = styled.table`
    width: 100%;
    border-spacing: 0;
    display: table;
    border-collapse: separate;
    border-color: ${colors.grey600};
`;

const TableHeadStyled = styled.th`
    text-align: ${(props) => props.align};
    border-bottom: 2px solid ${colors.grey500};
    color: ${colors.grey600};
    font-weight: 600;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 15px;
    word-break: break-all;
`;

const TitleDiv = styled.div`
    font: 600 15px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    margin-bottom: 20px;
    margin-top: 40px;
`;

class TemplateList extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.onCancelUpdateTemplate = this.onCancelUpdateTemplate.bind(this);
        this.reloadTemplates = this.reloadTemplates.bind(this);
        this.showError = this.showError.bind(this);
        this.closeModal = this.closeModal.bind(this);
        let serverTemplateListCopy = [];
        if (props.serverTemplateDetails) {
            serverTemplateListCopy = props.serverTemplateDetails.map((x) => x);

            if (props.domainTemplateDetails) {
                let domainTemplatesArray = props.domainTemplateDetails.map(
                    (template) => {
                        return template.templateName;
                    }
                );

                let domainTemplatesSet = new Set(domainTemplatesArray);
                serverTemplateListCopy = serverTemplateListCopy.filter(
                    (template) => !domainTemplatesSet.has(template.templateName)
                );
            }
        }

        this.state = {
            list: props.domainTemplateDetails || [],
            serverTemplateDetails: serverTemplateListCopy || [],
            successMessage: '',
            errorMessage: '',
            showError: false,
            showSuccess: false,
        };
    }

    showError(errorMessage) {
        this.setState({
            showError: true,
            errorMessage: errorMessage,
        });
    }

    reloadTemplates(successMessage) {
        this.props.api
            .getDomainTemplateDetailsList(this.props.domain)
            .then((data) => {
                let serverTemplateListCopy = [];
                if (this.props.serverTemplateDetails) {
                    serverTemplateListCopy =
                        this.props.serverTemplateDetails.map((x) => x);
                    if (data) {
                        let domainTemplatesArray = data.map((template) => {
                            return template.templateName;
                        });

                        let domainTemplatesSet = new Set(domainTemplatesArray);
                        serverTemplateListCopy = serverTemplateListCopy.filter(
                            (template) =>
                                !domainTemplatesSet.has(template.templateName)
                        );
                    }
                }

                this.setState({
                    list: data,
                    serverTemplateDetails: serverTemplateListCopy || [],
                    showSuccess: true,
                    successMessage,
                });

                // if template boarded, the policies and roles sorted in the store is out of date
                this.props.makeRolesAndPoliciesExpires();

                // this is to close the success alert
                setTimeout(
                    () =>
                        this.setState({
                            showSuccess: false,
                        }),
                    MODAL_TIME_OUT
                );
            })
            .catch((err) => {
                this.showError(RequestUtils.xhrErrorCheckHelper(err));
            });
    }

    onClickUpdateTemplate() {
        this.setState({
            showUpdate: true,
        });
    }

    closeModal() {
        this.setState({
            showError: false,
            errorMessage: '',
        });
    }

    onCancelUpdateTemplate() {
        this.setState({
            showUpdate: false,
            deleteServiceName: null,
        });
    }

    render() {
        const left = 'left';
        const center = 'center';
        const rows = this.state.list.map((item, i) => {
            let onClickUpdateTemplate = this.onClickUpdateTemplate.bind(this);
            const templateName = item.templateName;
            const templateDesc = item.description;
            let color = '';
            if (i % 2 === 0) {
                color = colors.row;
            }
            let toReturn = [];
            toReturn.push(
                <TemplateRow
                    templateName={templateName}
                    templateDesc={templateDesc}
                    timestamp={item.timestamp}
                    color={color}
                    api={this.api}
                    currentVersion={item.currentVersion}
                    latestVersion={item.latestVersion}
                    keywordsToReplace={item.keywordsToReplace}
                    _csrf={this.props._csrf}
                    key={templateName}
                    onClickUpdateTemplate={onClickUpdateTemplate}
                    domain={this.props.domain}
                    data={this.state.list}
                    onsubmit={this.reloadTemplates}
                    showError={this.showError}
                />
            );
            return toReturn;
        });
        const serverTemplateRows = this.state.serverTemplateDetails.map(
            (item, i) => {
                let onClickUpdateTemplate =
                    this.onClickUpdateTemplate.bind(this);
                const templateName = item.templateName;
                const templateDesc = item.description;
                let color = '';
                if (i % 2 === 0) {
                    color = colors.row;
                }
                let toReturn = [];
                toReturn.push(
                    <TemplateRow
                        templateName={templateName}
                        templateDesc={templateDesc}
                        timestamp={item.timestamp}
                        color={color}
                        api={this.api}
                        currentVersion={'N/A'}
                        latestVersion={item.latestVersion}
                        keywordsToReplace={item.keywordsToReplace}
                        _csrf={this.props._csrf}
                        key={templateName}
                        onClickUpdateTemplate={onClickUpdateTemplate}
                        domain={this.props.domain}
                        data={this.state.serverTemplateDetails}
                        onsubmit={this.reloadTemplates}
                        showError={this.showError}
                    />
                );
                return toReturn;
            }
        );
        return this.props.isLoading.length !== 0 ? (
            <ReduxPageLoader message={'Loading domain data'} />
        ) : (
            <TemplatesSectionDiv data-testid='template-list'>
                <TitleDiv>Domain Templates</TitleDiv>
                <TemplateTable>
                    <thead>
                        <tr>
                            <TableHeadStyled align={left}>
                                TEMPLATE
                            </TableHeadStyled>
                            <TableHeadStyled align={left}>INFO</TableHeadStyled>
                            <TableHeadStyled align={center}>
                                CURRENT VERSION
                            </TableHeadStyled>
                            <TableHeadStyled align={center}>
                                LATEST VERSION
                            </TableHeadStyled>
                            <TableHeadStyled align={center}>
                                UPDATED DATE
                            </TableHeadStyled>
                            <TableHeadStyled align={center}>
                                UPDATE VERSION
                            </TableHeadStyled>
                        </tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </TemplateTable>
                <TitleDiv>Server Templates</TitleDiv>
                <TemplateTable>
                    <thead>
                        <tr>
                            <TableHeadStyled align={left}>
                                TEMPLATE
                            </TableHeadStyled>
                            <TableHeadStyled align={left}>INFO</TableHeadStyled>
                            <TableHeadStyled align={center}>
                                CURRENT VERSION
                            </TableHeadStyled>
                            <TableHeadStyled align={center}>
                                LATEST VERSION
                            </TableHeadStyled>
                            <TableHeadStyled align={center}>
                                UPDATED DATE
                            </TableHeadStyled>
                            <TableHeadStyled align={center}>
                                UPDATE VERSION
                            </TableHeadStyled>
                        </tr>
                    </thead>
                    <tbody>{serverTemplateRows}</tbody>
                </TemplateTable>
                {this.state.showSuccess ? (
                    <Alert
                        isOpen={this.state.showSuccess}
                        title={this.state.successMessage}
                        onClose={this.closeModal}
                        type='success'
                    />
                ) : null}
                {this.state.showError ? (
                    <Alert
                        isOpen={this.state.showError}
                        title={this.state.errorMessage}
                        onClose={this.closeModal}
                        type='danger'
                    />
                ) : null}
            </TemplatesSectionDiv>
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        isLoading: selectIsLoading(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    makeRolesAndPoliciesExpires: () => {
        dispatch(makeRolesExpires());
        dispatch(makePoliciesExpires());
    },
});

export default connect(mapStateToProps, mapDispatchToProps)(TemplateList);
