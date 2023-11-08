import React from 'react';
import styled from '@emotion/styled';
import Loader from './Loader';

const LoaderDiv = styled.div`
    text-align: ${(props) => (props.textAlign ? props.textAlign : 'center')};
    padding-top: ${(props) => (props.paddingTop ? props.paddingTop : '20%')};
`;

const LoaderP = styled.p`
    font: 550 20px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    color: #3570f4;
`;

export class ReduxPageLoader extends React.PureComponent {
    render() {
        const { message, textAlign, paddingTop, size } = this.props;
        return (
            <LoaderDiv textAlign={textAlign} paddingTop={paddingTop}>
                <LoaderP>{message}</LoaderP>
                <Loader
                    size={size ? size : '50px'}
                    color={'#3570f4'}
                    verticalAlign={'bottom'}
                />
            </LoaderDiv>
        );
    }
}
