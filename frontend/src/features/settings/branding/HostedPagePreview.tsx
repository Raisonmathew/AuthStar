
import React from 'react';

export interface BrandingConfig {
    colors: {
        primary: string;
        background: string;
        text: string;
    };
    logo_url: string;
    show_watermark: boolean;
}

interface HostedPagePreviewProps {
    config: BrandingConfig;
    type?: 'login' | 'register';
}

export const HostedPagePreview: React.FC<HostedPagePreviewProps> = ({ config, type = 'login' }) => {
    const isLogin = type === 'login';

    return (
        <div className="w-full h-full flex items-center justify-center p-4 lg:p-8 overflow-auto custom-scrollbar">
            <div
                className="w-[400px] rounded-xl shadow-2xl overflow-hidden transition-all duration-200"
                style={{ backgroundColor: config.colors.background }}
            >
                <div className="p-8">
                    {config.logo_url ? (
                        <img src={config.logo_url} alt="Logo" className="h-10 mx-auto mb-8" />
                    ) : (
                        <div className="h-10 w-10 mx-auto mb-8 bg-gray-200 rounded-full flex items-center justify-center text-gray-400">
                            <span className="text-xs">LOGO</span>
                        </div>
                    )}

                    <h2
                        className="text-center text-2xl font-bold mb-8"
                        style={{ color: config.colors.text }}
                    >
                        {isLogin ? 'Sign in to your account' : 'Create an account'}
                    </h2>

                    <div className="space-y-4">
                        {!isLogin && (
                            <div>
                                <label className="block text-sm font-medium mb-1" style={{ color: config.colors.text }}>
                                    Full Name
                                </label>
                                <input
                                    type="text"
                                    disabled
                                    className="block w-full rounded-md border-gray-300 shadow-sm sm:text-sm p-2 border"
                                    placeholder="John Doe"
                                />
                            </div>
                        )}
                        <div>
                            <label className="block text-sm font-medium mb-1" style={{ color: config.colors.text }}>
                                Email address
                            </label>
                            <input
                                type="email"
                                disabled
                                className="block w-full rounded-md border-gray-300 shadow-sm sm:text-sm p-2 border"
                                placeholder="you@example.com"
                            />
                        </div>
                        <div>
                            <label className="block text-sm font-medium mb-1" style={{ color: config.colors.text }}>
                                Password
                            </label>
                            <input
                                type="password"
                                disabled
                                className="block w-full rounded-md border-gray-300 shadow-sm sm:text-sm p-2 border"
                                placeholder="••••••••"
                            />
                        </div>

                        <button
                            style={{ backgroundColor: config.colors.primary }}
                            className="w-full py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white hover:opacity-90 transition-opacity"
                        >
                            {isLogin ? 'Sign in' : 'Create Account'}
                        </button>

                        <div className="text-center text-sm">
                            <span style={{ color: config.colors.text, opacity: 0.7 }}>
                                {isLogin ? "Don't have an account? " : "Already have an account? "}
                            </span>
                            <a href="#" style={{ color: config.colors.primary }} className="font-medium hover:underline">
                                {isLogin ? 'Sign up' : 'Sign in'}
                            </a>
                        </div>
                    </div>
                </div>

                {config.show_watermark && (
                    <div className="bg-gray-50/50 px-8 py-4 border-t border-gray-100 text-center">
                        <p className="text-xs text-gray-400">Powered by IDaaS Platform</p>
                    </div>
                )}
            </div>
        </div>
    );
};
