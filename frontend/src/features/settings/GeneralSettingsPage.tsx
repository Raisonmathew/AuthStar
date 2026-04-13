import { useAuth } from '../auth/AuthContext';

export default function GeneralSettingsPage() {
    const { user } = useAuth();

    return (
        <div className="space-y-6">
            <div>
                <h3 className="text-lg font-semibold text-foreground font-heading mb-1">Tenant Settings</h3>
                <p className="text-sm text-muted-foreground">General configuration for your identity platform.</p>
            </div>

            <div className="bg-card rounded-xl border border-border p-6 space-y-4">
                <div>
                    <label className="block text-sm font-medium text-foreground mb-1">Tenant Name</label>
                    <input
                        type="text"
                        defaultValue="IDaaS Platform"
                        className="w-full px-3 py-2 bg-muted border border-border rounded-xl text-foreground text-sm focus:ring-2 focus:ring-ring focus:border-transparent"
                        readOnly
                    />
                </div>
                <div>
                    <label className="block text-sm font-medium text-foreground mb-1">Admin Email</label>
                    <input
                        type="text"
                        defaultValue={user?.email || ''}
                        className="w-full px-3 py-2 bg-muted border border-border rounded-xl text-foreground text-sm focus:ring-2 focus:ring-ring focus:border-transparent"
                        readOnly
                    />
                </div>
                <div>
                    <label className="block text-sm font-medium text-foreground mb-1">Environment</label>
                    <div className="flex items-center gap-2">
                        <span className="px-2.5 py-1 bg-amber-500/10 border border-amber-500/20 text-amber-500 text-xs font-medium rounded-full">
                            Development
                        </span>
                    </div>
                </div>
            </div>

            <div className="bg-card rounded-xl border border-border p-6">
                <h4 className="text-sm font-semibold text-foreground mb-3">Danger Zone</h4>
                <p className="text-sm text-muted-foreground mb-4">
                    Permanently delete this tenant and all associated data. This action cannot be undone.
                </p>
                <button className="px-4 py-2 bg-destructive/10 border border-destructive/20 text-destructive rounded-xl text-sm font-medium hover:bg-destructive/20 transition-colors" disabled>
                    Delete Tenant (Disabled in Dev)
                </button>
            </div>
        </div>
    );
}
