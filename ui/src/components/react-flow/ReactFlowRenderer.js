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
import React, { useCallback, useEffect, useRef, useState } from 'react';
import ReactFlow, {
    Background,
    Controls,
    isNode,
    MiniMap,
    Position,
    useEdgesState,
    useNodesState,
} from 'react-flow-renderer';

const getLayoutedElements = (elements, nodes, api, _csrf) => {
    let graphLayoutElements = [];
    let graphLayoutStyle = [];

    elements.forEach((el) => {
        if (!isNode(el)) {
            graphLayoutElements.push({
                data: {
                    id: el.id,
                    source: el.source,
                    target: el.target,
                },
            });
        } else {
            graphLayoutElements.push({
                data: {
                    id: el.id,
                },
            });
            graphLayoutStyle.push({
                selector: '#' + el.id,
                style: {
                    width: el.width,
                    height: el.height,
                },
            });
        }
    });

    return api.updateGraphLayout(graphLayoutElements, graphLayoutStyle, _csrf);
};

const nodeHasDimension = (el) => el.width && el.height;

const ReactFlowRenderer = (props) => {
    const { nodeTypes, api, _csrf } = props;
    const [shouldLayout, setShouldLayout] = useState(true);

    const [nodes, setNodes, onNodesChange] = useNodesState(props.nodes);
    const [edges, setEdges, onEdgesChange] = useEdgesState(props.edges);
    const onInit = useCallback((reactFlowInstance) => {
        reactFlowInstance.fitView({
            padding: 0.5,
        });
        reactFlowInstance.zoomTo(1);
    }, []);

    useEffect(() => {
        setShouldLayout(true);
    }, [props.nodes, props.edges]);

    useEffect(() => {
        if (
            shouldLayout &&
            nodes.length &&
            nodes.length > 0 &&
            nodes.every(nodeHasDimension)
        ) {
            const elements = [...nodes, ...edges];
            const elementsWithLayoutPromise = getLayoutedElements(
                elements,
                nodes,
                api,
                _csrf
            );
            const newNodes = [];
            const newEdges = [];
            elementsWithLayoutPromise
                .then((resultLayout) => {
                    elements.forEach((el) => {
                        if (isNode(el)) {
                            const nodeWithPosition = resultLayout[el.id];
                            el.targetPosition = Position.Left;
                            el.sourcePosition = Position.Right;

                            el.position = {
                                x:
                                    nodeWithPosition.x -
                                    el.width / 2 +
                                    Math.random() / 1000,
                                y: nodeWithPosition.y - el.height / 2,
                            };
                            newNodes.push(el);
                        } else {
                            newEdges.push(el);
                        }
                    });
                    setNodes(newNodes);
                    setEdges(newEdges);
                    setShouldLayout(false);
                })
                .catch((err) => {
                    if (err.statusCode === 0) {
                        window.location.reload();
                    }
                });
        }
    }, [shouldLayout, nodes]);

    return (
        <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            elementsSelectable={false}
            selectNodesOnDrag={true}
            nodeTypes={nodeTypes}
            onInit={onInit}
            fitView
        >
            <Background
                variant='dots'
                gap={24}
                size={1}
                color={'#FFFFFF'}
                style={{ background: `rgb(248, 248, 248)` }}
            />
            <Controls />
            <MiniMap
                nodeColor={(node) => {
                    switch (node.type) {
                        case 'primaryNode':
                            return 'LightBlue';
                        case 'inboundNode':
                            return 'LightGreen';
                        case 'outboundNode':
                            return 'red';
                        default:
                            return '#eee';
                    }
                }}
            />
        </ReactFlow>
    );
};

export default ReactFlowRenderer;
