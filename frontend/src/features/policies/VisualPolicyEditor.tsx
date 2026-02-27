/**
 * Enhanced Visual Policy Editor
 *
 * ReactFlow-based policy builder that syncs with EIAA AST format.
 * Supports drag-and-drop policy step composition.
 */

import { useCallback, useMemo, useState } from 'react';
import ReactFlow, {
    addEdge,
    MiniMap,
    Controls,
    Background,
    useNodesState,
    useEdgesState,
    Connection,
    Edge,
    Node,
    Handle,
    Position,
    NodeProps,
} from 'reactflow';
import 'reactflow/dist/style.css';

// ============================================
// Custom Node Types
// ============================================

function StartNode({ data }: NodeProps) {
    return (
        <div className="px-4 py-2 bg-green-100 border-2 border-green-500 rounded-lg shadow-md">
            <div className="flex items-center gap-2">
                <span>🚀</span>
                <span className="font-semibold text-green-800">{data.label}</span>
            </div>
            <Handle type="source" position={Position.Bottom} className="w-3 h-3 !bg-green-500" />
        </div>
    );
}

function StepNode({ data }: NodeProps) {
    const iconMap: Record<string, string> = {
        verify_identity: '🔍',
        require_factor: '🔐',
        evaluate_risk: '📊',
        authorize_action: '✅',
        collect_credentials: '📝',
        require_verification: '✉️',
    };

    return (
        <div className="px-4 py-3 bg-white border-2 border-blue-400 rounded-lg shadow-md min-w-[160px]">
            <Handle type="target" position={Position.Top} className="w-3 h-3 !bg-blue-400" />
            <div className="flex items-center gap-2">
                <span className="text-lg">{iconMap[data.stepType] || '⚙️'}</span>
                <div>
                    <div className="font-semibold text-gray-800">{data.label}</div>
                    {data.detail && (
                        <div className="text-xs text-gray-500">{data.detail}</div>
                    )}
                </div>
            </div>
            <Handle type="source" position={Position.Bottom} className="w-3 h-3 !bg-blue-400" />
        </div>
    );
}

function ConditionalNode({ data }: NodeProps) {
    return (
        <div className="px-4 py-3 bg-yellow-50 border-2 border-yellow-500 rounded-lg shadow-md">
            <Handle type="target" position={Position.Top} className="w-3 h-3 !bg-yellow-500" />
            <div className="flex items-center gap-2">
                <span className="text-lg">🔀</span>
                <div>
                    <div className="font-semibold text-yellow-800">{data.label}</div>
                    <div className="text-xs text-yellow-600">{data.condition}</div>
                </div>
            </div>
            <Handle
                type="source"
                position={Position.Bottom}
                id="then"
                className="w-3 h-3 !bg-green-500 left-1/4"
            />
            <Handle
                type="source"
                position={Position.Bottom}
                id="else"
                className="w-3 h-3 !bg-red-500 left-3/4"
            />
        </div>
    );
}

function DecisionNode({ data }: NodeProps) {
    const isAllow = data.allow;
    return (
        <div
            className={`px-4 py-2 ${isAllow ? 'bg-green-100 border-green-500' : 'bg-red-100 border-red-500'
                } border-2 rounded-lg shadow-md`}
        >
            <Handle type="target" position={Position.Top} className="w-3 h-3 !bg-gray-400" />
            <div className="flex items-center gap-2">
                <span>{isAllow ? '✅' : '❌'}</span>
                <span className={`font-semibold ${isAllow ? 'text-green-800' : 'text-red-800'}`}>
                    {data.label}
                </span>
            </div>
        </div>
    );
}

const nodeTypes = {
    start: StartNode,
    step: StepNode,
    conditional: ConditionalNode,
    decision: DecisionNode,
};

// ============================================
// Step Palette
// ============================================

const stepPalette = [
    { type: 'verify_identity', label: 'Verify Identity', icon: '🔍' },
    { type: 'require_factor', label: 'Require Factor', icon: '🔐' },
    { type: 'evaluate_risk', label: 'Evaluate Risk', icon: '📊' },
    { type: 'collect_credentials', label: 'Collect Credentials', icon: '📝' },
    { type: 'require_verification', label: 'Require Verification', icon: '✉️' },
    { type: 'conditional', label: 'If/Then', icon: '🔀' },
];

// ============================================
// Main Component
// ============================================

interface VisualPolicyEditorProps {
    initialSpec: any;
    onChange: (spec: any) => void;
}

export default function VisualPolicyEditor({ initialSpec, onChange }: VisualPolicyEditorProps) {
    const [nodeIdCounter, setNodeIdCounter] = useState(10);

    // Convert AST to nodes/edges
    const { initialNodes, initialEdges } = useMemo(() => {
        const nodes: Node[] = [
            {
                id: 'start',
                type: 'start',
                position: { x: 250, y: 50 },
                data: { label: 'Start' },
            },
        ];

        const edges: Edge[] = [];
        let y = 150;

        // Parse initial spec sequence
        const sequence = initialSpec?.sequence || [];
        let prevId = 'start';

        sequence.forEach((step: any, index: number) => {
            const nodeId = `step-${index}`;

            if (step.allow !== undefined) {
                nodes.push({
                    id: nodeId,
                    type: 'decision',
                    position: { x: 250, y },
                    data: { label: step.allow ? 'Allow' : 'Deny', allow: step.allow },
                });
            } else if (step.condition) {
                nodes.push({
                    id: nodeId,
                    type: 'conditional',
                    position: { x: 250, y },
                    data: { label: 'Condition', condition: JSON.stringify(step.condition) },
                });
            } else {
                const stepType = Object.keys(step)[0];
                nodes.push({
                    id: nodeId,
                    type: 'step',
                    position: { x: 250, y },
                    data: {
                        label: stepType.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase()),
                        stepType,
                        detail: JSON.stringify(step[stepType]),
                    },
                });
            }

            edges.push({ id: `e-${prevId}-${nodeId}`, source: prevId, target: nodeId });
            prevId = nodeId;
            y += 100;
        });

        // Add default decision if none exists
        if (!sequence.some((s: any) => s.allow !== undefined)) {
            const endId = 'end-allow';
            nodes.push({
                id: endId,
                type: 'decision',
                position: { x: 250, y },
                data: { label: 'Allow', allow: true },
            });
            edges.push({ id: `e-${prevId}-${endId}`, source: prevId, target: endId });
        }

        return { initialNodes: nodes, initialEdges: edges };
    }, [initialSpec]);

    const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
    const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

    const onConnect = useCallback(
        (params: Connection) => {
            setEdges((eds) => addEdge(params, eds));
        },
        [setEdges]
    );

    // Add step from palette
    const addStep = (stepType: string) => {
        const newId = `step-${nodeIdCounter}`;
        setNodeIdCounter((c) => c + 1);

        const newNode: Node = {
            id: newId,
            type: stepType === 'conditional' ? 'conditional' : 'step',
            position: { x: 100 + Math.random() * 300, y: 200 + Math.random() * 200 },
            data: {
                label: stepType.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase()),
                stepType,
            },
        };

        setNodes((nds) => [...nds, newNode]);
    };

    // Sync to AST on change (simplified)
    const handleSave = () => {
        // Convert nodes back to AST sequence
        const sequence = nodes
            .filter((n) => n.type === 'step' || n.type === 'decision')
            .sort((a, b) => a.position.y - b.position.y)
            .map((n) => {
                if (n.type === 'decision') {
                    return { allow: n.data.allow };
                }
                return { [n.data.stepType]: {} };
            });

        onChange({
            version: 'EIAA-AST-1.0',
            sequence,
        });
    };

    return (
        <div className="flex flex-col gap-4">
            {/* Step Palette */}
            <div className="flex gap-2 p-3 bg-gray-100 dark:bg-gray-700 rounded-lg overflow-x-auto">
                <span className="text-sm font-medium text-gray-600 dark:text-gray-300 self-center mr-2">
                    Add Step:
                </span>
                {stepPalette.map((item) => (
                    <button
                        key={item.type}
                        onClick={() => addStep(item.type)}
                        className="flex items-center gap-1 px-3 py-2 bg-white dark:bg-gray-600 border border-gray-200 dark:border-gray-500 rounded-lg hover:bg-blue-50 dark:hover:bg-blue-900 transition-colors text-sm"
                    >
                        <span>{item.icon}</span>
                        <span>{item.label}</span>
                    </button>
                ))}
            </div>

            {/* Canvas */}
            <div className="relative" style={{ width: '100%', height: '500px' }}>
                <ReactFlow
                    nodes={nodes}
                    edges={edges}
                    onNodesChange={onNodesChange}
                    onEdgesChange={onEdgesChange}
                    onConnect={onConnect}
                    nodeTypes={nodeTypes}
                    fitView
                >
                    <Controls />
                    <MiniMap
                        nodeColor={(n) => {
                            switch (n.type) {
                                case 'start':
                                    return '#22c55e';
                                case 'decision':
                                    return n.data.allow ? '#22c55e' : '#ef4444';
                                case 'conditional':
                                    return '#eab308';
                                default:
                                    return '#3b82f6';
                            }
                        }}
                    />
                    <Background gap={16} size={1} />
                </ReactFlow>

                {/* Save Button */}
                <button
                    onClick={handleSave}
                    className="absolute bottom-4 right-4 px-4 py-2 bg-blue-600 text-white rounded-lg shadow-lg hover:bg-blue-700 transition-colors"
                >
                    💾 Sync to Policy
                </button>
            </div>
        </div>
    );
}
