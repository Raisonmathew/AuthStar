import React, { useEffect, useState } from 'react';
import { policiesApi, Policy } from '../lib/api/policies';
import { PolicyEditor } from '../features/policies/PolicyEditor';

export const AdminPoliciesPage: React.FC = () => {
    const [policies, setPolicies] = useState<Policy[]>([]);
    const [isEditing, setIsEditing] = useState(false);
    const [loading, setLoading] = useState(true);

    const fetchPolicies = async () => {
        setLoading(true);
        try {
            const data = await policiesApi.list();
            setPolicies(data);
        } catch (error) {
            console.error('Failed to list policies', error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchPolicies();
    }, []);

    return (
        <div className="container mx-auto px-4 py-8">
            <div className="flex justify-between items-center mb-6">
                <h1 className="text-2xl font-bold">Organization Policies</h1>
                <button
                    onClick={() => setIsEditing(true)}
                    className="bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded"
                >
                    + New Policy Version
                </button>
            </div>

            {isEditing && (
                <div className="mb-8">
                    <PolicyEditor
                        onSuccess={() => { setIsEditing(false); fetchPolicies(); }}
                        onCancel={() => setIsEditing(false)}
                    />
                </div>
            )}

            {loading ? (
                <div>Loading...</div>
            ) : (
                <div className="bg-white shadow-md rounded my-6 overflow-x-auto">
                    <table className="min-w-full table-auto">
                        <thead>
                            <tr className="bg-gray-200 text-gray-600 uppercase text-sm leading-normal">
                                <th className="py-3 px-6 text-left">Action</th>
                                <th className="py-3 px-6 text-left">Version</th>
                                <th className="py-3 px-6 text-left">Created At</th>
                                <th className="py-3 px-6 text-left">Spec Preview</th>
                            </tr>
                        </thead>
                        <tbody className="text-gray-600 text-sm font-light">
                            {policies.map((policy) => (
                                <tr key={policy.id} className="border-b border-gray-200 hover:bg-gray-100">
                                    <td className="py-3 px-6 text-left whitespace-nowrap font-medium">{policy.action}</td>
                                    <td className="py-3 px-6 text-left">{policy.version}</td>
                                    <td className="py-3 px-6 text-left">{new Date(policy.created_at).toLocaleString()}</td>
                                    <td className="py-3 px-6 text-left max-w-xs truncate">
                                        {JSON.stringify(policy.spec)}
                                    </td>
                                </tr>
                            ))}
                            {policies.length === 0 && (
                                <tr>
                                    <td colSpan={4} className="py-4 text-center">No custom policies found. Using defaults.</td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
};
