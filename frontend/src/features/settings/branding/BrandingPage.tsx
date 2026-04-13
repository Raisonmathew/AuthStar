import { useState, useEffect } from 'react';
import { useAuth } from '../../../features/auth/hooks/useAuth';
import { api } from '../../../lib/api';
import { toast } from 'sonner';
import { HostedPagePreview, BrandingConfig } from './HostedPagePreview'; // Import shared type and component

// Re-using the interface from the component file or keeping local if preferred, 
// but ensure consistency. Since it's exported from HostedPagePreview, let's use that one.
// However, the previous code had DEFAULT_CONFIG locally. Let's keep a local default.

const DEFAULT_CONFIG: BrandingConfig = {
    colors: {
        primary: '#4F46E5', // Indigo 600
        background: '#ffffff',
        text: '#111827', // Gray 900
    },
    logo_url: '',
    show_watermark: true
};

export default function BrandingPage() {
    const { organizationId } = useAuth();
    const [config, setConfig] = useState<BrandingConfig>(DEFAULT_CONFIG);
    const [saving, setSaving] = useState(false);
    const [previewType, setPreviewType] = useState<'login' | 'register'>('login');

    useEffect(() => {
        if (organizationId) {
            loadBranding();
        }
    }, [organizationId]);

    const loadBranding = async () => {
        if (!organizationId) return;
        try {
            const res = await api.get<{
                branding?: {
                    primary_color?: string;
                    background_color?: string;
                    text_color?: string;
                    logo_url?: string;
                };
            }>(`/api/organizations/${organizationId}`);
            // Initialize config if it exists
            if (res.data && res.data.branding) {
                const backendBranding = res.data.branding;
                setConfig({
                    colors: {
                        primary: backendBranding.primary_color || DEFAULT_CONFIG.colors.primary,
                        background: backendBranding.background_color || DEFAULT_CONFIG.colors.background,
                        text: backendBranding.text_color || DEFAULT_CONFIG.colors.text,
                    },
                    logo_url: backendBranding.logo_url || '',
                    show_watermark: true
                });
            }
        } catch (error) {
            console.error(error);
            toast.error('Failed to load branding configuration');
        }
    };

    const handleSave = async () => {
        if (!organizationId) return;
        setSaving(true);
        try {
            // Map local config to backend structure
            const payload = {
                logo_url: config.logo_url || null,
                primary_color: config.colors.primary,
                background_color: config.colors.background,
                text_color: config.colors.text,
                font_family: 'Inter' // Default for now
            };

            await api.patch(`/api/organizations/${organizationId}/branding`, payload);
            toast.success('Branding updated successfully');
        } catch (error) {
            console.error(error);
            toast.error('Failed to update branding');
        } finally {
            setSaving(false);
        }
    };

    return (
        <div className="h-[calc(100vh-theme(spacing.32))] flex flex-col lg:flex-row gap-6">
            {/* Editor Panel */}
            <div className="w-full lg:w-1/3 bg-card backdrop-blur-sm rounded-2xl border border-border flex flex-col overflow-hidden">
                <div className="p-6 border-b border-border bg-muted/30">
                    <h2 className="text-xl font-bold text-foreground font-heading">Visual Editor</h2>
                    <p className="mt-1 text-sm text-muted-foreground">Customize the look of your hosted pages.</p>
                </div>

                <div className="flex-1 overflow-y-auto p-6 space-y-8 custom-scrollbar">
                    {/* Colors Section */}
                    <div>
                        <h3 className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-4 font-heading">Color Palette</h3>
                        <div className="space-y-5">
                            <div>
                                <label className="block text-sm font-medium text-foreground mb-2">Primary Color</label>
                                <div className="flex items-center gap-3">
                                    <div className="relative group">
                                        <div className="absolute inset-0 rounded-xl bg-white/10 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none" />
                                        <input
                                            type="color"
                                            value={config.colors.primary}
                                            onChange={e => setConfig({ ...config, colors: { ...config.colors, primary: e.target.value } })}
                                            className="h-12 w-12 rounded-xl border border-border cursor-pointer p-1 bg-card"
                                        />
                                    </div>
                                    <input
                                        type="text"
                                        value={config.colors.primary}
                                        onChange={e => setConfig({ ...config, colors: { ...config.colors, primary: e.target.value } })}
                                        className="flex-1 bg-muted rounded-xl border-border text-foreground shadow-sm focus:border-primary focus:ring-ring sm:text-sm font-mono uppercase px-4 py-3"
                                    />
                                </div>
                                <p className="mt-2 text-xs text-muted-foreground">Used for buttons, links, and accents.</p>
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-foreground mb-2">Background Color</label>
                                <div className="flex items-center gap-3">
                                    <input
                                        type="color"
                                        value={config.colors.background}
                                        onChange={e => setConfig({ ...config, colors: { ...config.colors, background: e.target.value } })}
                                        className="h-12 w-12 rounded-xl border border-border cursor-pointer p-1 bg-card"
                                    />
                                    <input
                                        type="text"
                                        value={config.colors.background}
                                        onChange={e => setConfig({ ...config, colors: { ...config.colors, background: e.target.value } })}
                                        className="flex-1 bg-muted rounded-xl border-border text-foreground shadow-sm focus:border-primary focus:ring-ring sm:text-sm font-mono uppercase px-4 py-3"
                                    />
                                </div>
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-foreground mb-2">Text Color</label>
                                <div className="flex items-center gap-3">
                                    <input
                                        type="color"
                                        value={config.colors.text}
                                        onChange={e => setConfig({ ...config, colors: { ...config.colors, text: e.target.value } })}
                                        className="h-12 w-12 rounded-xl border border-border cursor-pointer p-1 bg-card"
                                    />
                                    <input
                                        type="text"
                                        value={config.colors.text}
                                        onChange={e => setConfig({ ...config, colors: { ...config.colors, text: e.target.value } })}
                                        className="flex-1 bg-muted rounded-xl border-border text-foreground shadow-sm focus:border-primary focus:ring-ring sm:text-sm font-mono uppercase px-4 py-3"
                                    />
                                </div>
                            </div>
                        </div>
                    </div>

                    <div className="h-px bg-border" />

                    {/* Logo Section */}
                    <div>
                        <h3 className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-4 font-heading">Brand Assets</h3>
                        <div>
                            <label className="block text-sm font-medium text-foreground mb-2">Logo URL</label>
                            <input
                                type="text"
                                value={config.logo_url}
                                onChange={e => setConfig({ ...config, logo_url: e.target.value })}
                                placeholder="https://example.com/logo.png"
                                className="block w-full bg-muted rounded-xl border-border text-foreground shadow-sm focus:border-primary focus:ring-ring sm:text-sm px-4 py-3 placeholder-muted-foreground"
                            />
                            <p className="mt-2 text-xs text-muted-foreground">Publicly accessible URL for your organization's logo.</p>
                        </div>
                    </div>

                    <div className="h-px bg-border" />

                    {/* Settings Section */}
                    <div>
                        <h3 className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-4 font-heading">Preferences</h3>
                        <label className="flex items-start cursor-pointer group">
                            <div className="flex items-center h-6">
                                <input
                                    id="watermark"
                                    type="checkbox"
                                    checked={config.show_watermark}
                                    onChange={e => setConfig({ ...config, show_watermark: e.target.checked })}
                                    className="w-5 h-5 rounded border-border text-primary focus:ring-ring bg-card transition-all"
                                />
                            </div>
                            <div className="ml-3 text-sm">
                                <span className="font-medium text-foreground group-hover:text-foreground/80 transition-colors">Display "Powered by IDaaS"</span>
                                <p className="text-muted-foreground mt-0.5">Show the IDaaS watermark on your hosted pages.</p>
                            </div>
                        </label>
                    </div>
                </div>

                <div className="p-6 border-t border-border bg-muted/30">
                    <button
                        onClick={handleSave}
                        disabled={saving}
                        className="w-full inline-flex justify-center items-center py-3 px-4 border border-transparent shadow-lg text-sm font-bold font-heading rounded-xl text-primary-foreground bg-primary hover:bg-primary/90 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-ring disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200"
                    >
                        {saving ? (
                            <>
                                <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zM12 20a8 8 0 01-8-8H0c0 6.627 5.373 12 12 12v-4z"></path>
                                </svg>
                                Saving...
                            </>
                        ) : 'Save Configuration'}
                    </button>
                </div>
            </div>

            {/* Preview Panel */}
            <div className="flex-1 bg-muted/30 rounded-2xl border border-border overflow-hidden flex flex-col relative">
                <div className="absolute inset-0 bg-grid-slate-800/[0.2] bg-[length:32px_32px] pointer-events-none" />

                <div className="bg-card/80 backdrop-blur-md border-b border-border p-4 flex justify-between items-center px-6 relative z-10">
                    <div className="flex items-center gap-2">
                        <div className="w-3 h-3 rounded-full bg-red-500/20 border border-red-500/50" />
                        <div className="w-3 h-3 rounded-full bg-amber-500/20 border border-amber-500/50" />
                        <div className="w-3 h-3 rounded-full bg-emerald-500/20 border border-emerald-500/50" />
                    </div>

                    <span className="text-xs font-bold text-muted-foreground uppercase tracking-wider font-heading">Live Preview</span>

                    <div className="flex bg-muted rounded-lg p-1 border border-border">
                        <button
                            onClick={() => setPreviewType('login')}
                            className={`px-4 py-1.5 text-xs font-medium rounded-md transition-all duration-200 ${previewType === 'login'
                                ? 'bg-accent text-foreground shadow-sm'
                                : 'text-muted-foreground hover:text-foreground'
                                }`}
                        >
                            Sign In
                        </button>
                        <button
                            onClick={() => setPreviewType('register')}
                            className={`px-4 py-1.5 text-xs font-medium rounded-md transition-all duration-200 ${previewType === 'register'
                                ? 'bg-accent text-foreground shadow-sm'
                                : 'text-muted-foreground hover:text-foreground'
                                }`}
                        >
                            Sign Up
                        </button>
                    </div>
                </div>

                <div className="flex-1 relative flex items-center justify-center p-8 overflow-hidden">
                    <HostedPagePreview config={config} type={previewType} />
                </div>
            </div>
        </div>
    );
}
