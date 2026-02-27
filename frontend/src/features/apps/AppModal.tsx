import { useState } from 'react';
import { api } from '../../lib/api';
import { toast } from 'sonner';

interface AppModalProps {
    app?: { id: string; name: string; redirect_uris: string[] };
    onClose: () => void;
    onSuccess: () => void;
}

export default function AppModal({ app, onClose, onSuccess }: AppModalProps) {
    const [name, setName] = useState(app?.name || '');
    const [redirectUris, setRedirectUris] = useState(app?.redirect_uris.join(', ') || '');
    const isEditing = Boolean(app);
    const [createdApp, setCreatedApp] = useState<{ id: string; client_id: string; client_secret: string } | null>(null);
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);

        const uris = redirectUris.split(',').map(u => u.trim()).filter(Boolean);

        try {
            if (isEditing && app) {
                await api.put(`/admin/v1/apps/${app.id}`, {
                    name,
                    redirect_uris: uris,
                });
                toast.success('Application updated successfully');
                onSuccess();
                onClose();
            } else {
                const res = await api.post('/admin/v1/apps', {
                    name,
                    redirect_uris: uris,
                });
                // res.data is { app: {}, client_secret: "" }
                setCreatedApp({
                    id: res.data.app.id,
                    client_id: res.data.app.client_id,
                    client_secret: res.data.client_secret,
                });
                toast.success('Application created successfully');
                onSuccess();
            }
        } catch (err: any) {
            console.error(err);
            toast.error('Failed to create application');
        } finally {
            setLoading(false);
        }
    };

    if (createdApp) {
        return (
            <div className="fixed z-10 inset-0 overflow-y-auto" aria-labelledby="modal-title" role="dialog" aria-modal="true">
                <div className="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
                    <div className="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" aria-hidden="true"></div>
                    <span className="hidden sm:inline-block sm:align-middle sm:h-screen" aria-hidden="true">&#8203;</span>

                    <div className="inline-block align-bottom bg-white rounded-lg px-4 pt-5 pb-4 text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full sm:p-6">
                        <div>
                            <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100">
                                <svg className="h-6 w-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7" />
                                </svg>
                            </div>
                            <div className="mt-3 text-center sm:mt-5">
                                <h3 className="text-lg leading-6 font-medium text-gray-900" id="modal-title">
                                    Application Created
                                </h3>
                                <div className="mt-2">
                                    <p className="text-sm text-gray-500">
                                        Please copy your Client Secret now. It will not be shown again.
                                    </p>
                                    <div className="mt-4 text-left bg-gray-50 p-3 rounded border border-gray-200">
                                        <div className="mb-2">
                                            <label className="block text-xs font-medium text-gray-500 uppercase">Client ID</label>
                                            <code className="block text-sm font-mono text-gray-800 break-all">{createdApp.client_id}</code>
                                        </div>
                                        <div>
                                            <label className="block text-xs font-medium text-gray-500 uppercase">Client Secret</label>
                                            <code className="block text-sm font-mono text-red-600 break-all">{createdApp.client_secret}</code>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div className="mt-5 sm:mt-6">
                            <button
                                type="button"
                                className="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-indigo-600 text-base font-medium text-white hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 sm:text-sm"
                                onClick={onClose}
                            >
                                I have copied the secret
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="fixed z-10 inset-0 overflow-y-auto" aria-labelledby="modal-title" role="dialog" aria-modal="true">
            <div className="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
                <div className="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" onClick={onClose} aria-hidden="true"></div>

                <span className="hidden sm:inline-block sm:align-middle sm:h-screen" aria-hidden="true">&#8203;</span>

                <div className="inline-block align-bottom bg-white rounded-lg px-4 pt-5 pb-4 text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full sm:p-6">
                    <div>
                        <h3 className="text-lg leading-6 font-medium text-gray-900" id="modal-title">
                            {isEditing ? 'Edit Application' : 'Create New Application'}
                        </h3>
                        <div className="mt-2 text-sm text-gray-500">
                            {isEditing ? 'Update application settings.' : 'Create a new OIDC client for your project.'}
                        </div>
                        <form className="mt-5 space-y-4" onSubmit={handleSubmit}>
                            <div>
                                <label htmlFor="name" className="block text-sm font-medium text-gray-700">App Name</label>
                                <input
                                    type="text"
                                    name="name"
                                    id="name"
                                    required
                                    className="mt-1 shadow-sm focus:ring-indigo-500 focus:border-indigo-500 block w-full sm:text-sm border-gray-300 rounded-md p-2 border"
                                    placeholder="My Cool App"
                                    value={name}
                                    onChange={(e) => setName(e.target.value)}
                                />
                            </div>
                            <div>
                                <label htmlFor="redirect-uris" className="block text-sm font-medium text-gray-700">Redirect URIs (comma separated)</label>
                                <input
                                    type="text"
                                    name="redirect-uris"
                                    id="redirect-uris"
                                    required
                                    className="mt-1 shadow-sm focus:ring-indigo-500 focus:border-indigo-500 block w-full sm:text-sm border-gray-300 rounded-md p-2 border"
                                    placeholder="http://localhost:3000/callback, https://app.com/callback"
                                    value={redirectUris}
                                    onChange={(e) => setRedirectUris(e.target.value)}
                                />
                            </div>
                            <div className="mt-5 sm:mt-6 sm:grid sm:grid-cols-2 sm:gap-3 sm:grid-flow-row-dense">
                                <button
                                    type="submit"
                                    disabled={loading}
                                    className="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-indigo-600 text-base font-medium text-white hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 sm:col-start-2 sm:text-sm"
                                >
                                    {loading ? 'Saving...' : (isEditing ? 'Save Changes' : 'Create')}
                                </button>
                                <button
                                    type="button"
                                    className="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 sm:mt-0 sm:col-start-1 sm:text-sm"
                                    onClick={onClose}
                                >
                                    Cancel
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    );
}
