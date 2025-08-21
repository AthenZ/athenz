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
import Switch from '../denali/Switch';
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import DeleteModal from '../modal/DeleteModal';
import Color from '../denali/Color';
import DateUtils from '../utils/DateUtils';
import RequestUtils from '../utils/RequestUtils';
import { css, keyframes } from '@emotion/react';
import { deleteSubDomain } from '../../redux/thunks/domains';
import { connect } from 'react-redux';
import { withRouter } from 'next/router';
import { selectBusinessServices } from '../../redux/selectors/domainData';
import {
    selectBusinessServicesAll,
    selectTimeZone,
} from '../../redux/selectors/domains';
import OnCallTeamModal from '../modal/OnCallTeamModal';
import { MODAL_TIME_OUT } from '../constants/constants';
import Alert from '../denali/Alert';

const ManageDomainSectionDiv = styled.div`
    margin: 20px;
`;

const AddContainerDiv = styled.div`
    padding-bottom: 20px;
`;

const RoleTable = styled.table`
    width: 100%;
    border-spacing: 0;
    display: table;
    border-collapse: separate;
    border-color: grey;
`;

const TableHeadStyled = styled.th`
    text-align: ${(props) => props.align};
    border-bottom: 2px solid #d5d5d5;
    color: #9a9a9a;
    font-weight: 600;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 15px;
    word-break: break-all;
`;

const TDStyled = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
`;

const TDStyledOnCallTeam = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    title: ${(props) => props.title};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 1px;
`;

const StyledAnchor = styled.a`
    color: ${colors.linkActive};
    text-decoration: none;
    cursor: pointer;
    font-weight: '';
`;

const TrStyled = styled.tr`
    ${(props) =>
        props.isSuccess === true &&
        css`
            animation: ${colorTransition} 3s ease;
        `}
`;

const colorTransition = keyframes`
        0% {
            background-color: rgba(21, 192, 70, 0.20);
        }
        100% {
            background-color: transparent;
        }
`;

class ManageDomains extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.state = {
            showDelete: false,
            auditEnabled: false,
            auditRef: '',
            errorMessage: null,
            showBusinessService: false,
            businessServiceName: '',
            businessServiceDomainName: '',
            category: 'domain',
            errorMessageForModal: '',
            showOnCallModal: false,
            domain: '',
            onCall: '',
            showSuccess: false,
        };
        this.saveJustification = this.saveJustification.bind(this);
        this.saveBusinessService = this.saveBusinessService.bind(this);
        this.domainNameProvided = this.domainNameProvided.bind(this);
        this.onBusinessServiceInputChange =
            this.onBusinessServiceInputChange.bind(this);
        this.dateUtils = new DateUtils();
    }

    onClickBusinessService(domainName, businessServiceName, auditEnabled) {
        this.setState({
            showBusinessService: true,
            businessServiceName: businessServiceName,
            businessServiceDomainName: domainName,
            auditEnabled: auditEnabled,
        });
    }

    onClickBusinessServiceCancel() {
        this.setState({
            showBusinessService: false,
            errorMessageForModal: '',
            errorMessage: null,
            businessServiceName: '',
            businessServiceDomainName: '',
            auditRef: '',
            auditEnabled: false,
        });
    }

    onClickDelete(name, auditEnabled) {
        this.setState({
            showDelete: true,
            deleteName: name,
            auditEnabled: auditEnabled,
        });
    }

    onClickDeleteCancel() {
        this.setState({
            showDelete: false,
            deleteName: '',
            auditEnabled: false,
            auditRef: '',
            errorMessage: null,
        });
    }

    saveJustification(val) {
        this.setState({
            auditRef: val,
        });
    }
    saveBusinessService(val) {
        this.setState({
            businessServiceName: val,
            errorMessageForModal: '',
        });
    }

    onBusinessServiceInputChange(val) {
        this.setState({
            businessServiceInInput: val,
        });
    }

    domainNameProvided(val) {
        this.setState({
            domainNameProvided: val,
        });
    }

    ascertainDomainType(domain) {
        if (domain) {
            var splits = domain.split('.');
            if (splits.length === 2 && domain.indexOf('home.') === 0) {
                return 'Personal';
            }

            if (splits.length >= 2) {
                return 'Sub domain';
            }

            return 'Top Level';
        }
        return '';
    }

    onSubmitDelete() {
        let domainName = this.state.deleteName;

        if (domainName !== this.state.domainNameProvided) {
            this.setState({
                errorMessageForModal: 'Domain names do not match',
            });
            return;
        }

        const splittedDomain = domainName.split('.');
        const domain = splittedDomain.pop();
        const parent = splittedDomain.join('.');
        this.props
            .deleteSubDomain(
                parent,
                domain,
                this.state.auditRef,
                this.props._csrf
            )
            .then(() => {
                this.setState({
                    showDelete: false,
                    deleteName: null,
                    auditEnabled: false,
                    auditRef: '',
                    errorMessage: null,
                });
                this.props.loadDomains(
                    `Successfully deleted domain ${domainName}`
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                    showDelete: false,
                    deleteName: null,
                    auditEnabled: false,
                    auditRef: '',
                });
            });
    }

    updateMeta(meta, domainName, csrf) {
        let auditMsg = this.state.auditRef;
        if (auditMsg === '') {
            auditMsg = 'Updated ' + domainName + ' Meta using Athenz UI';
        }
        this.api
            .putMeta(
                domainName,
                domainName,
                meta,
                auditMsg,
                csrf,
                this.state.category
            )
            .then(() => {
                this.setState({
                    showDelete: false,
                    deleteName: null,
                    auditEnabled: false,
                    auditRef: '',
                    errorMessage: null,
                    errorMessageForModal: '',
                    showBusinessService: false,
                    businessServiceName: '',
                    businessServiceDomainName: '',
                });
                this.props.loadDomains(domainName);
            })
            .catch((err) => {
                this.setState({
                    errorMessageForModal: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    onClickOnCallTeam(domain, onCall) {
        this.setState({
            showOnCallModal: true,
            domain: domain,
            onCall: onCall,
        });
    }

    onClickOnCallTeamCancel() {
        this.setState({
            showOnCallModal: false,
        });
    }

    onUpdateOnCallTeamSuccessCb(teamName) {
        this.setState({
            showOnCallModal: false,
            onCall: teamName,
            showSuccess: true,
            successMessage: 'Successfully updated on call team',
        });

        this.props.loadDomains('Successfully updated on call team');

        setTimeout(
            () =>
                this.setState({
                    showSuccess: false,
                }),
            MODAL_TIME_OUT + 1000
        );
    }

    closeModal() {
        this.setState({ showSuccess: false });
    }

    onSubmitBusinessService() {
        if (this.state.auditEnabled && !this.state.auditRef) {
            this.setState({
                errorMessageForModal: 'Justification is mandatory',
            });
            return;
        }

        if (this.state.businessServiceInInput) {
            const colonIdx = this.state.businessServiceName.indexOf(':');
            if (colonIdx === -1 && this.state.businessServiceInInput) {
                // text is in input but the service name is not selected
                this.setState({
                    errorMessageForModal:
                        'Business Service must be selected in the dropdown',
                });
                return;
            }
        }

        if (this.state.businessServiceName) {
            var index = this.props.validBusinessServicesAll.findIndex(
                (x) =>
                    x.value ==
                    this.state.businessServiceName.substring(
                        0,
                        this.state.businessServiceName.indexOf(':')
                    )
            );
            if (index === -1) {
                this.setState({
                    errorMessageForModal: 'Invalid business service value',
                });
                return;
            }
        }

        let domainName = this.state.businessServiceDomainName;
        let businessServiceName = this.state.businessServiceName;
        let domainMeta = {};
        domainMeta.businessService = businessServiceName
            ? businessServiceName
            : '';
        this.updateMeta(domainMeta, domainName, this.props._csrf);
    }

    render() {
        const left = 'left';
        const center = 'center';
        const rows = this.props.domains
            ? this.props.domains.map((item, i) => {
                  const domainType = this.ascertainDomainType(item.domain.name);
                  let isSuccess =
                      item.domain.name === this.props.successMessage;
                  let deletable = false;
                  let auditEnabled = !!item.domain.auditEnabled;
                  let deleteItem = this.onClickDelete.bind(
                      this,
                      item.domain.name,
                      auditEnabled
                  );

                  let color = '';
                  if (i % 2 === 0) {
                      color = colors.row;
                  }
                  if (domainType === 'Sub domain') {
                      deletable = true;
                  }

                  let title = item.domain.onCall ?? 'add';

                  return (
                      <TrStyled key={item.domain.name} isSuccess={isSuccess}>
                          <TDStyled color={color} align={left}>
                              {item.domain.name}
                          </TDStyled>
                          <TDStyled color={color} align={left}>
                              {domainType}
                          </TDStyled>
                          <TDStyled color={color} align={left}>
                              {this.dateUtils.getLocalDate(
                                  item.domain.modified,
                                  this.props.timeZone,
                                  this.props.timeZone
                              )}
                          </TDStyled>
                          <TDStyled color={color} align={center}>
                              {item.domain.productId
                                  ? item.domain.productId
                                  : ''}
                          </TDStyled>
                          <TDStyled color={color} align={center}>
                              <Switch
                                  name={'selfServe-' + i}
                                  value={auditEnabled}
                                  checked={auditEnabled}
                                  disabled
                              />
                          </TDStyled>
                          <TDStyled color={color} align={center}>
                              {item.domain.account ? item.domain.account : ''}
                          </TDStyled>
                          <TDStyled color={color} align={center}>
                              {item.domain.gcpProject}
                          </TDStyled>
                          <TDStyledOnCallTeam
                              color={color}
                              align={center}
                              title={title}
                          >
                              <StyledAnchor
                                  onClick={this.onClickOnCallTeam.bind(
                                      this,
                                      item.domain.name,
                                      item.domain.onCall
                                  )}
                              >
                                  {title}
                              </StyledAnchor>
                          </TDStyledOnCallTeam>
                          <TDStyled color={color} align={center}>
                              {deletable ? (
                                  <Icon
                                      icon={'trash'}
                                      onClick={deleteItem}
                                      color={colors.icons}
                                      isLink
                                      size={'1.25em'}
                                      verticalAlign={'text-bottom'}
                                      id={item.domain.name + '-delete-button'}
                                  />
                              ) : null}
                          </TDStyled>
                      </TrStyled>
                  );
              })
            : '';
        if (this.state.showDelete) {
            let clickDeleteCancel = this.onClickDeleteCancel.bind(this);
            let clickDeleteSubmit = this.onSubmitDelete.bind(this);
            rows.push(
                <DeleteModal
                    isOpen={this.state.showDelete}
                    cancel={clickDeleteCancel}
                    message={
                        'Are you sure you want to permanently delete the Domain '
                    }
                    name={this.state.deleteName}
                    submit={clickDeleteSubmit}
                    showJustification={this.state.auditEnabled}
                    showDomainInput={true}
                    onJustification={this.saveJustification}
                    key={'delete-modal'}
                    errorMessage={this.state.errorMessageForModal}
                    domainNameProvided={this.domainNameProvided}
                />
            );
        }

        if (this.state.showOnCallModal) {
            rows.push(
                <OnCallTeamModal
                    domain={this.state.domain}
                    title='OnCall Team'
                    isOpen={this.state.showOnCallModal}
                    onCancel={this.onClickOnCallTeamCancel.bind(this)}
                    onUpdateOnCallTeamSuccessCb={this.onUpdateOnCallTeamSuccessCb.bind(
                        this
                    )}
                    onCallTeamName={this.state.onCall}
                    csrf={this.props._csrf}
                    api={this.api}
                />
            );
        }

        return (
            <ManageDomainSectionDiv data-testid='manage-domains'>
                <AddContainerDiv />
                {this.state.errorMessage && (
                    <Color name={'red600'}>{this.state.errorMessage}</Color>
                )}
                {this.state.showSuccess ? (
                    <Alert
                        isOpen={this.state.showSuccess}
                        title={this.state.successMessage}
                        onClose={this.closeModal.bind(this)}
                        type='success'
                    />
                ) : null}
                <RoleTable>
                    <thead>
                        <tr>
                            <TableHeadStyled align={left}>Name</TableHeadStyled>
                            <TableHeadStyled align={left}>Type</TableHeadStyled>
                            <TableHeadStyled align={left}>
                                Modified Date
                            </TableHeadStyled>
                            <TableHeadStyled align={center}>
                                Product Master Id
                            </TableHeadStyled>
                            <TableHeadStyled align={center}>
                                Audit
                            </TableHeadStyled>
                            <TableHeadStyled align={center}>
                                AWS Account #
                            </TableHeadStyled>
                            <TableHeadStyled align={center}>
                                GCP Project ID
                            </TableHeadStyled>
                            <TableHeadStyled align={center}>
                                ONCALL TEAM
                            </TableHeadStyled>
                            <TableHeadStyled align={center}>
                                Delete
                            </TableHeadStyled>
                        </tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </RoleTable>
            </ManageDomainSectionDiv>
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        validBusinessServices: selectBusinessServices(state),
        validBusinessServicesAll: selectBusinessServicesAll(state),
        timeZone: selectTimeZone(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    deleteSubDomain: (parentDomain, domain, auditRef, _csrf) =>
        dispatch(deleteSubDomain(parentDomain, domain, auditRef, _csrf)),
});

export default connect(
    mapStateToProps,
    mapDispatchToProps
)(withRouter(ManageDomains));
