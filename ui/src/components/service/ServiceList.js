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
import Button from '../denali/Button';
import NameUtils from '../utils/NameUtils';
import Alert from '../denali/Alert';
import DeleteModal from '../modal/DeleteModal';
import { MODAL_TIME_OUT } from '../constants/constants';
import RequestUtils from '../utils/RequestUtils';
import ServiceRow from './ServiceRow';
import AddService from './AddService';
import { deleteService } from '../../redux/thunks/services';
import { connect } from 'react-redux';
import { selectServices } from '../../redux/selectors/services';
import { selectIsLoading } from '../../redux/selectors/loading';
import {
    selectTimeZone,
    selectFeatureFlag,
} from '../../redux/selectors/domains';
import { ReduxPageLoader } from '../denali/ReduxPageLoader';

const ServicesSectionDiv = styled.div`
    margin: 20px;
`;

const AddContainerDiv = styled.div`
    padding-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-flow: row nowrap;
    float: right;
`;

const ServiceTable = styled.table`
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

const StyledAnchor = styled.a`
    color: #3570f4;
    text-decoration: none;
    cursor: pointer;
`;

class ServiceList extends React.Component {
    constructor(props) {
        super(props);
        this.onCancelDeleteService = this.onCancelDeleteService.bind(this);
        this.toggleAddService = this.toggleAddService.bind(this);
        this.reloadServices = this.reloadServices.bind(this);
        this.closeModal = this.closeModal.bind(this);
        this.onSubmitDeleteService = this.onSubmitDeleteService.bind(this);
        this.state = {};
    }

    onSubmitDeleteService() {
        this.props
            .deleteService(
                this.props.domain,
                this.state.deleteServiceName,
                this.props._csrf
            )
            .then(() => {
                this.reloadServices(
                    `Successfully deleted service ${this.state.deleteServiceName}`,
                    true
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    onCancelDeleteService() {
        this.setState({
            showDelete: false,
            deleteServiceName: null,
        });
    }

    onClickDeleteService(serviceName) {
        this.setState({
            showDelete: true,
            deleteServiceName: serviceName,
            errorMessage: null,
        });
    }

    buildServiceRows(services) {
        const rows = services
            ? services.map((item, i) => {
                  const serviceName = NameUtils.getShortName('.', item.name);
                  let newService = serviceName === this.state.successMessage;
                  let onClickDeleteService = this.onClickDeleteService.bind(
                      this,
                      serviceName
                  );
                  let color = '';
                  if (i % 2 === 0) {
                      color = colors.row;
                  }
                  let toReturn = [];
                  toReturn.push(
                      <ServiceRow
                          serviceName={serviceName}
                          domainName={this.props.domain}
                          modified={item.modified}
                          newService={newService}
                          color={color}
                          key={item.name}
                          timeZone={this.props.timeZone}
                          featureFlag={this.props.featureFlag}
                          _csrf={this.props._csrf}
                          onClickDeleteService={onClickDeleteService}
                      />
                  );
                  return toReturn;
              })
            : [];
        return rows;
    }

    componentDidMount() {
        this.setState({
            rows: this.buildServiceRows(this.props.services),
        });
    }

    componentDidUpdate(prevProps) {
        if (this.props.services !== prevProps.services) {
            this.setState({
                rows: this.buildServiceRows(this.props.services),
            });
        }
    }

    //successMessage is only name of new service when adding a service
    reloadServices(successMessage, showSuccess) {
        this.setState({
            showAddService: false,
            showSuccess,
            successMessage,
            showDelete: false,
        });
        setTimeout(
            () =>
                this.setState({
                    showSuccess: false,
                }),
            MODAL_TIME_OUT
        );
    }

    closeModal() {
        this.setState({ showSuccess: false });
    }

    toggleAddService() {
        this.setState({
            showAddService: !this.state.showAddService,
        });
    }

    render() {
        const { domain } = this.props;
        const left = 'left';
        const center = 'center';

        let addService = this.state.showAddService ? (
            <AddService
                showAddService={this.state.showAddService}
                onCancel={this.toggleAddService}
                onSubmit={this.reloadServices}
                domain={domain}
                _csrf={this.props._csrf}
                pageConfig={this.props.pageConfig}
            />
        ) : (
            ''
        );
        return this.props.isLoading.length !== 0 ? (
            <ReduxPageLoader message={'Loading services data'} />
        ) : (
            <ServicesSectionDiv data-testid='service-list'>
                <AddContainerDiv>
                    <div>
                        <Button secondary onClick={this.toggleAddService}>
                            Add Service
                        </Button>
                        {addService}
                    </div>
                </AddContainerDiv>
                <ServiceTable>
                    <thead>
                        <tr>
                            <TableHeadStyled align={left}>
                                Service
                            </TableHeadStyled>
                            <TableHeadStyled align={left}>
                                Modified Date
                            </TableHeadStyled>
                            {this.props.featureFlag ? (
                                <TableHeadStyled align={center}>
                                    Instances
                                </TableHeadStyled>
                            ) : null}
                            <TableHeadStyled align={center}>
                                Public Keys
                            </TableHeadStyled>
                            <TableHeadStyled align={center}>
                                Tags
                            </TableHeadStyled>
                            <TableHeadStyled align={center}>
                                MSD Policies
                            </TableHeadStyled>
                            <TableHeadStyled align={center}>
                                Providers
                            </TableHeadStyled>
                            <TableHeadStyled align={center}>
                                Delete
                            </TableHeadStyled>
                        </tr>
                    </thead>
                    <tbody>{this.state.rows}</tbody>
                </ServiceTable>
                {this.state.showSuccess ? (
                    <Alert
                        isOpen={this.state.showSuccess}
                        title={this.state.successMessage}
                        onClose={this.closeModal}
                        type='success'
                    />
                ) : null}
                {this.state.showDelete ? (
                    <DeleteModal
                        name={this.state.deleteServiceName}
                        isOpen={this.state.showDelete}
                        cancel={this.onCancelDeleteService}
                        submit={this.onSubmitDeleteService}
                        errorMessage={this.state.errorMessage}
                        message={
                            'Are you sure you want to permanently delete the Service '
                        }
                    />
                ) : null}
            </ServicesSectionDiv>
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        isLoading: selectIsLoading(state),
        services: selectServices(state),
        featureFlag: selectFeatureFlag(state),
        timeZone: selectTimeZone(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    deleteService: (domainName, serviceName, _csrf) =>
        dispatch(deleteService(domainName, serviceName, _csrf)),
});

export default connect(mapStateToProps, mapDispatchToProps)(ServiceList);
