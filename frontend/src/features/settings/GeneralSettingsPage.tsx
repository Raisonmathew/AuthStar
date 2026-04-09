import { useAuth } from '../auth/AuthContext';

export default function GeneralSettingsPage() {
    const { user } = useAuth();

    return (
        <div className="space-y-6">
            <div>
                <h3 className="text-lg font-semibold text-white mb-1">Tenant Settings</h3>
                <p className="text-sm text-slate-400">General configuration for your identity platform.</p>
            </div>

            <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-6 space-y-4">
                <div>
                    <label className="block text-sm font-medium text-slate-300 mb-1">Tenant Name</label>
                    <input
                        type="text"
                        defaultValue="IDaaS Platform"
                        className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white text-sm focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                        readOnly
                    />
                </div>
                <div>
                    <label className="block text-sm font-medium text-slate-300 mb-1">Admin Email</label>
                    <input
                        type="text"
                        defaultValue={user?.email || ''}
                        className="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white text-sm focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                        readOnly
                    />
                </div>
                <div>
                    <label className="block text-sm font-medium text-slate-300 mb-1">Environment</label>
                    <div className="flex items-center gap-2">
                        <span className="px-2.5 py-1 bg-amber-500/10 border border-amber-500/20 text-amber-400 text-xs font-medium rounded-full">
                            Development
                        </span>
                    </div>
                </div>
            </div>

            <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-6">
                <h4 className="text-sm font-semibold text-white mb-3">Danger Zone</h4>
                <p className="text-sm text-slate-400 mb-4">
                    Permanently delete this tenant and all associated data. This action cannot be undone.
                </p>
                <button className="px-4 py-2 bg-red-500/10 border border-red-500/20 text-red-400 rounded-lg text-sm font-medium hover:bg-red-500/20 transition-colors" disabled>
                    Delete Tenant (Disabled in Dev)
                </button>
            </div>
        </div>
    );
}
