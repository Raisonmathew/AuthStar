/**
 * Auth Flow Preview Component
 *
 * Visual preview of the authentication flow based on current login methods config.
 * Shows the step sequence that users will experience.
 */

import { useMemo } from 'react';

interface LoginMethodsConfig {
    email_password: boolean;
    passkey: boolean;
    sso: boolean;
    mfa: {
        required: boolean;
        methods: string[];
    };
    require_email_verification?: boolean;
}

interface FlowStep {
    id: string;
    label: string;
    type: 'start' | 'input' | 'choice' | 'verify' | 'decision';
    icon: string;
}

interface AuthFlowPreviewProps {
    config: LoginMethodsConfig;
    flowType: 'login' | 'signup';
}

export default function AuthFlowPreview({ config, flowType }: AuthFlowPreviewProps) {
    const steps = useMemo(() => {
        const result: FlowStep[] = [];

        if (flowType === 'login') {
            // Login flow
            result.push({
                id: 'start',
                label: 'Start',
                type: 'start',
                icon: '🚀',
            });

            // Choice or single auth method
            if (config.passkey && config.email_password) {
                result.push({
                    id: 'choice',
                    label: 'Choose Method',
                    type: 'choice',
                    icon: '🔀',
                });
                result.push({
                    id: 'passkey',
                    label: 'Passkey',
                    type: 'input',
                    icon: '🔑',
                });
                result.push({
                    id: 'password',
                    label: 'Email + Password',
                    type: 'input',
                    icon: '🔐',
                });
            } else if (config.passkey) {
                result.push({
                    id: 'passkey',
                    label: 'Passkey',
                    type: 'input',
                    icon: '🔑',
                });
            } else {
                result.push({
                    id: 'email',
                    label: 'Email',
                    type: 'input',
                    icon: '📧',
                });
                result.push({
                    id: 'password',
                    label: 'Password',
                    type: 'input',
                    icon: '🔐',
                });
            }

            // MFA if required
            if (config.mfa?.required) {
                result.push({
                    id: 'mfa',
                    label: config.mfa.methods.includes('totp') ? 'OTP Verification' : 'MFA',
                    type: 'verify',
                    icon: '📱',
                });
            }
        } else {
            // Signup flow
            result.push({
                id: 'start',
                label: 'Start',
                type: 'start',
                icon: '🚀',
            });

            result.push({
                id: 'credentials',
                label: 'Enter Details',
                type: 'input',
                icon: '📝',
            });

            if (config.require_email_verification !== false) {
                result.push({
                    id: 'verify-email',
                    label: 'Verify Email',
                    type: 'verify',
                    icon: '✉️',
                });
            }
        }

        // Always end with decision
        result.push({
            id: 'decision',
            label: 'Allow',
            type: 'decision',
            icon: '✅',
        });

        return result;
    }, [config, flowType]);

    return (
        <div className="bg-white dark:bg-gray-800 rounded-xl p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                {flowType === 'login' ? '🔐 Login Flow' : '📝 Signup Flow'} Preview
            </h3>

            <div className="flex items-center gap-2 overflow-x-auto pb-4">
                {steps.map((step, index) => (
                    <div key={step.id} className="flex items-center">
                        <div
                            className={`flex flex-col items-center min-w-[100px] p-4 rounded-lg border-2 ${step.type === 'start'
                                    ? 'bg-green-50 border-green-300 dark:bg-green-900/20 dark:border-green-700'
                                    : step.type === 'decision'
                                        ? 'bg-blue-50 border-blue-300 dark:bg-blue-900/20 dark:border-blue-700'
                                        : step.type === 'choice'
                                            ? 'bg-yellow-50 border-yellow-300 dark:bg-yellow-900/20 dark:border-yellow-700'
                                            : 'bg-gray-50 border-gray-200 dark:bg-gray-700 dark:border-gray-600'
                                }`}
                        >
                            <span className="text-2xl mb-2">{step.icon}</span>
                            <span className="text-sm font-medium text-gray-700 dark:text-gray-200 text-center">
                                {step.label}
                            </span>
                        </div>
                        {index < steps.length - 1 && (
                            <div className="mx-2 text-gray-400 dark:text-gray-500">→</div>
                        )}
                    </div>
                ))}
            </div>

            <div className="mt-4 text-xs text-gray-500 dark:text-gray-400 border-t border-gray-200 dark:border-gray-700 pt-4">
                <p>
                    This preview shows the authentication steps users will experience based on your
                    current configuration.
                </p>
            </div>
        </div>
    );
}
