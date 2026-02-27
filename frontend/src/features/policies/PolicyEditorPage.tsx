
import { useEffect, useState } from 'react';
import { api } from '../../lib/api';
import { toast } from 'sonner';
import { Policy } from './types';
import { Link } from 'react-router-dom';

export default function PolicyEditorPage() {
    const [policies, setPolicies] = useState<Policy[]>([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchPolicies = async () => {
            try {
                const res = await api.get<Policy[]>('/admin/v1/policies');
                setPolicies(res.data);
            } catch (err) {
                console.error(err);
                toast.error('Failed to fetch policies');
            } finally {
                setLoading(false);
            }
        };
        fetchPolicies();
    }, []);

    return (
        <div>
            <div className="flex justify-between items-center">
                <div>
                    <h3 className="text-lg font-medium text-gray-900">Policy Management</h3>
                    <p className="mt-1 text-sm text-gray-500">
                        Create and edit EIAA policies (Capsules).
                    </p>
                </div>
                <Link to="/admin/policies/new" className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700">
                    Create New Policy
                </Link>
            </div>

            <div className="mt-6 bg-white shadow overflow-hidden sm:rounded-md">
                <ul className="divide-y divide-gray-200">
                    {loading ? (
                        <li className="px-4 py-4 text-center text-gray-500">Loading...</li>
                    ) : policies.length === 0 ? (
                        <li className="px-4 py-4 text-center text-gray-500">No policies found.</li>
                    ) : (
                        policies.map((policy) => (
                            <li key={policy.id}>
                                <Link to={`/admin/policies/${policy.id}`} className="block hover:bg-gray-50">
                                    <div className="px-4 py-4 sm:px-6">
                                        <div className="flex items-center justify-between">
                                            <div className="flex flex-col">
                                                <p className="text-sm font-medium text-indigo-600 truncate">{policy.action} (v{policy.version})</p>
                                                <p className="text-sm text-gray-500">ID: <span className="font-mono text-xs">{policy.id}</span></p>
                                            </div>
                                            <div className="flex items-center">
                                                <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-gray-100 text-gray-800">
                                                    {new Date(policy.created_at).toLocaleDateString()}
                                                </span>
                                            </div>
                                        </div>
                                    </div>
                                </Link>
                            </li>
                        ))
                    )}
                </ul>
            </div>
        </div>
    );
}
