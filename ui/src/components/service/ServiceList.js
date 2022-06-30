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
import {colors} from '../denali/styles';
import Button from '../denali/Button';
import NameUtils from '../utils/NameUtils';
import Alert from '../denali/Alert';
import DeleteModal from '../modal/DeleteModal';
import {MODAL_TIME_OUT} from '../constants/constants';
import RequestUtils from '../utils/RequestUtils';
import ServiceRow from './ServiceRow';
import AddService from './AddService';
import {deleteService} from '../../redux/thunks/services';
import {connect} from 'react-redux';

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
    font-size: 0.8rem;
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

class SeviceList extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.onCancelDeleteService = this.onCancelDeleteService.bind(this);
        this.toggleAddService = this.toggleAddService.bind(this);
        this.reloadServices = this.reloadServices.bind(this);
        this.closeModal = this.closeModal.bind(this);
        this.onSubmitDeleteService = this.onSubmitDeleteService.bind(this);
        this.state = {
            list: props.services || [],
        };
    }

    onSubmitDeleteService() {
        let onSuccess = () => {
            this.reloadServices(
                `Successfully deleted service ${this.state.deleteServiceName}`,
                true
            );
        };

        let onFail = (err) => {
            this.setState({
                errorMessage: RequestUtils.xhrErrorCheckHelper(err),
            });
        };

        this.props.deleteService(
            this.state.deleteServiceName,
            this.props._csrf,
            onSuccess,
            onFail
        );
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

    // componentDidUpdate(prevProps) {
    //     console.log(
    //         'in update because props changed',
    //         prevProps.services,
    //         'curr props: ',
    //         this.props.services
    //     );
    //     if (
    //         this.props.services.length !== prevProps.services.length ||
    //         this.props.services.every(
    //             (value, index) => value !== prevProps.services[index]
    //         )
    //     ) {
    //         console.log('in array check because props changed');
    //         this.setState({
    //             list: this.props.services,
    //         });
    //         setTimeout(
    //             () =>
    //                 this.setState({
    //                     showSuccess: false,
    //                 }),
    //             MODAL_TIME_OUT
    //         );
    //     }
    // }

    //TODO roy - mobeit into componentDidUpdtae
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
        this.setState({showSuccess: false});
    }

    toggleAddService() {
        this.setState({
            showAddService: !this.state.showAddService,
        });
    }

    render() {
        const {domain} = this.props;
        const left = 'left';
        const center = 'center';

        // TODO roy - move it into componentDidUpdate
        const rows = this.props.services
            ? this.props.services.map((item, i) => {
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
                        domainName={domain}
                        modified={item.modified}
                        newService={newService}
                        color={color}
                        api={this.api}
                        key={item.name}
                        _csrf={this.props._csrf}
                        onClickDeleteService={onClickDeleteService}
                        featureFlag={this.props.featureFlag}
                    />
                );
                return toReturn;
            })
            : [];
        let addService = this.state.showAddService ? (
            <AddService
                showAddService={this.state.showAddService}
                onCancel={this.toggleAddService}
                onSubmit={this.reloadServices}
                domain={domain}
                api={this.api}
                _csrf={this.props._csrf}
                pageConfig={this.props.pageConfig}
            />
        ) : (
            ''
        );
        return (
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
                        <TableHeadStyled align={center}>
                            Instances
                        </TableHeadStyled>
                        <TableHeadStyled align={center}>
                            Public Keys
                        </TableHeadStyled>
                        <TableHeadStyled align={center}>
                            Providers
                        </TableHeadStyled>
                        <TableHeadStyled align={center}>
                            Delete
                        </TableHeadStyled>
                    </tr>
                    </thead>
                    <tbody>{rows}</tbody>
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
        isLoading: state.isLoading,
        services: state.services.services,
    };
};

const mapDispatchToProps = (dispatch) => ({
    deleteService: (serviceName, _csrf, onSuccess, onFail) =>
        dispatch(deleteService(serviceName, _csrf, onSuccess, onFail)),
});

export default connect(mapStateToProps, mapDispatchToProps)(SeviceList);
