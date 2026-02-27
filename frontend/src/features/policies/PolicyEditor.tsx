import React, { useState } from 'react';
import { policiesApi } from '../../lib/api/policies';

interface PolicyEditorProps {
    onSuccess: () => void;
    onCancel: () => void;
}

export const PolicyEditor: React.FC<PolicyEditorProps> = ({ onSuccess, onCancel }) => {
    const [action, setAction] = useState('signup');
    const [specJson, setSpecJson] = useState(JSON.stringify({
        version: "EIAA-AST-1.0",
        sequence: [
            {
                "VerifyIdentity": {
                    "source": "Primary"
                }
            },
            {
                "Allow": true
            }
        ]
    }, null, 2));
    const [error, setError] = useState<string | null>(null);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError(null);

        try {
            const spec = JSON.parse(specJson);
            await policiesApi.create({ action, spec });
            onSuccess();
        } catch (err: any) {
            setError(err.message || 'Failed to save policy. Ensure JSON is valid.');
        }
    };

    return (
        <div className="bg-white p-6 rounded-lg shadow-lg">
            <h2 className="text-xl font-bold mb-4">Edit Policy</h2>
            {error && (
                <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
                    {error}
                </div>
            )}
            <form onSubmit={handleSubmit}>
                <div className="mb-4">
                    <label className="block text-gray-700 text-sm font-bold mb-2">Action</label>
                    <select
                        value={action}
                        onChange={(e) => setAction(e.target.value)}
                        className="shadow border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
                    >
                        <option value="signup">Sign Up</option>
                        <option value="signin">Sign In</option>
                    </select>
                </div>

                <div className="mb-4">
                    <label className="block text-gray-700 text-sm font-bold mb-2">Policy Spec (JSON)</label>
                    <textarea
                        value={specJson}
                        onChange={(e) => setSpecJson(e.target.value)}
                        className="shadow border rounded w-full py-2 px-3 text-gray-700 font-mono text-sm h-64 focus:outline-none focus:shadow-outline"
                    />
                </div>

                <div className="flex justify-end gap-2">
                    <button type="button" onClick={onCancel} className="bg-gray-500 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded">
                        Cancel
                    </button>
                    <button type="submit" className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">
                        Save New Version
                    </button>
                </div>
            </form>
        </div>
    );
};
