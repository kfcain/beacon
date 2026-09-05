import React from 'react';
import {createRoot} from 'react-dom/client';
import Workspace from '../../components/beacon/workspace';
import Product from '../../app/product/page';
import '../../app/globals.css';
import '../../app/beacon.css';
import '../../app/marketing.css';
createRoot(document.getElementById('root')!).render(location.pathname==='/product'?<Product/>:<Workspace initialView={location.pathname==='/trust'?'Trust center':'Overview'}/>);
