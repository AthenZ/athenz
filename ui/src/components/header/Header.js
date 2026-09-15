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
import NavBar from '../denali/NavBar';
import NavBarItem from '../denali/NavBarItem';
import styled from '@emotion/styled';
import HeaderMenu from './HeaderMenu';
import Search from '../search/Search';
import Link from 'next/link';
import PageUtils from '../utils/PageUtils';
import { useRouter } from 'next/router';
import { colors } from '../denali/styles';

const Logo = ({ className }) => (
    <img src='/static/athenz-logo-full.png' className={className} />
);

const LogoStyled = styled(Logo)`
    height: 36px;
    cursor: pointer;
`;

const NavBarDiv = styled.div`
    height: 60px;
    position: relative;
`;

const NavBarItemDiv = styled.div`
    margin-left: 10%;
    width: 50%;
`;

const HeaderRightDiv = styled.div`
    display: flex;
    align-items: center;
`;

const SelfServiceLink = styled('a', {
    shouldForwardProp: (prop) => prop !== 'active',
})`
    color: ${colors.white};
    cursor: pointer;
    display: flex;
    align-items: center;
    font: 300 16px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    height: 60px;
    margin-right: 8px;
    padding: 0 12px;
    text-decoration: none;
    white-space: nowrap;
    box-shadow: ${(props) =>
        props.active ? `inset 0 -4px 0 ${colors.brand600}` : 'none'};
    &:hover {
        color: rgba(255, 255, 255, 0.75);
    }
`;

const Header = (props) => {
    const router = useRouter();
    let search = '';
    if (props.showSearch) {
        search = <Search isHeader={true} searchData={props.searchData} />;
    }
    const selfServiceActive = router?.pathname === '/self-service';
    return (
        <NavBarDiv data-testid='header'>
            <NavBar background={'#002339'}>
                <NavBarItem>
                    <Link href={PageUtils.homePage()}>
                        <LogoStyled />
                    </Link>
                </NavBarItem>
                <NavBarItemDiv>
                    <NavBarItem width='100%'>{search}</NavBarItem>
                </NavBarItemDiv>
                <NavBarItem right>
                    <HeaderRightDiv>
                        <Link
                            href={PageUtils.selfServicePage()}
                            passHref
                            legacyBehavior
                        >
                            <SelfServiceLink
                                active={selfServiceActive}
                                data-testid='self-service-nav'
                            >
                                Self Service
                            </SelfServiceLink>
                        </Link>
                        <HeaderMenu />
                    </HeaderRightDiv>
                </NavBarItem>
            </NavBar>
        </NavBarDiv>
    );
};

export default Header;
