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
import styled from '@emotion/styled';
import Switch from '../denali/Switch';
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import DeleteModal from '../modal/DeleteModal';
import Color from '../denali/Color';
import DateUtils from '../utils/DateUtils';
import RequestUtils from '../utils/RequestUtils';

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
    font-size: 0.8rem;
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

export default class ManageDomains extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.state = {
            showDelete: false,
            auditEnabled: false,
            auditRef: '',
        };
        this.saveJustification = this.saveJustification.bind(this);
        this.dateUtils = new DateUtils();
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
        });
    }

    saveJustification(val) {
        this.setState({
            auditRef: val,
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
        const splittedDomain = domainName.split('.');
        const domain = splittedDomain.pop();
        const parent = splittedDomain.join('.');
        this.api
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

    render() {
        const left = 'left';
        const center = 'center';
        const rows = this.props.domains
            ? this.props.domains.map((item, i) => {
                  const domainType = this.ascertainDomainType(item.domain.name);
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
                  return (
                      <tr key={item.domain.name}>
                          <TDStyled color={color} align={left}>
                              {item.domain.name}
                          </TDStyled>
                          <TDStyled color={color} align={left}>
                              {domainType}
                          </TDStyled>
                          <TDStyled color={color} align={left}>
                              {this.dateUtils.getLocalDate(
                                  item.domain.modified,
                                  'UTC',
                                  'UTC'
                              )}
                          </TDStyled>
                          <TDStyled color={color} align={center}>
                              {item.domain.ypmId ? item.domain.ypmId : ''}
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
                              {deletable ? (
                                  <Icon
                                      icon={'trash'}
                                      onClick={deleteItem}
                                      color={colors.icons}
                                      isLink
                                      size={'1.25em'}
                                      verticalAlign={'text-bottom'}
                                  />
                              ) : null}
                          </TDStyled>
                      </tr>
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
                    onJustification={this.saveJustification}
                    key={'delete-modal'}
                />
            );
        }

        return (
            <ManageDomainSectionDiv data-testid='manage-domains'>
                <AddContainerDiv />
                {this.state.errorMessage && (
                    <Color name={'red600'}>{this.state.errorMessage}</Color>
                )}
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
