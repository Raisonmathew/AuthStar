/**
 * EIAA-Compliant Auth Flow Page
 * 
 * This is a UNIVERSAL flow renderer. It:
 * - Renders EXACTLY what the backend tells it
 * - Never makes security decisions
 * - Never validates meaning
 * - Operates as a deterministic FSM
 */

import React, { useReducer, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { toast } from 'sonner';

// ============================================
// TYPES - Matching backend hosted.rs types
// ============================================

type FlowIntent = 'login' | 'signup' | 'resetpassword';

interface CredentialField {
    name: string;
    label: string;
    required: boolean;
    format?: string;
    min_length?: number;
}

interface FactorOption {
    type: string;
    label: string;
}

type UiStep =
    | { type: 'email'; label: string; required: boolean }
    | { type: 'password'; label: string }
    | { type: 'otp'; label: string }
    | { type: 'passkey_challenge'; session_id: string; options: any; user_id: string }
    | { type: 'credentials'; fields: CredentialField[] }
    | { type: 'email_verification'; label: string; email: string }
    | { type: 'factor_choice'; options: FactorOption[] }
    | { type: 'reset_code_verification'; label: string; email: string }  // EIAA: Password reset
    | { type: 'new_password'; label: string; hint?: string }  // EIAA: Password reset
    | { type: 'error'; message: string };

// ============================================
// EIAA CONTEXT TYPES
// ============================================

interface EiaaContext {
    acceptableCapabilities: string[];
    requiredAal: string;
    achievedAal: string | null;
    riskLevel: string;
    orgName?: string;
    branding?: any;
}

const defaultEiaaContext: EiaaContext = {
    acceptableCapabilities: [],
    requiredAal: 'AAL1',
    achievedAal: null,
    riskLevel: 'Low',
};

type FlowState =
    | 'INIT'
    | 'FLOW_INIT'
    | 'RENDER_STEP'
    | 'SUBMITTING'
    | 'ERROR_RECOVERABLE'
    | 'ERROR_FATAL'
    | 'DECISION_READY'
    | 'REDIRECT';

// ============================================
// FSM STATES & EVENTS
// ============================================

interface State {
    flowState: FlowState;
    flowId: string | null;
    currentStep: UiStep | null;
    errorMessage: string | null;
    decisionRef: string | null;
    eiaa: EiaaContext;
}

type FlowEvent =
    | { type: 'START_FLOW' }
    | { type: 'FLOW_CREATED'; flowId: string; uiStep: UiStep; eiaa: EiaaContext }
    | { type: 'SUBMIT_STEP' }
    | { type: 'STEP_RESPONSE'; uiStep: UiStep; eiaa: Partial<EiaaContext> }
    | { type: 'DECISION_READY'; decisionRef: string; achievedAal?: string }
    | { type: 'NETWORK_ERROR'; message: string }
    | { type: 'RETRY' }
    | { type: 'RESTART' }
    | { type: 'COMMIT_CONFIRMED' };

// ============================================
// FSM REDUCER
// ============================================

function flowReducer(state: State, event: FlowEvent): State {
    switch (event.type) {
        case 'START_FLOW':
            return { ...state, flowState: 'FLOW_INIT' };

        case 'FLOW_CREATED':
            return {
                ...state,
                flowState: 'RENDER_STEP',
                flowId: event.flowId,
                currentStep: event.uiStep,
                eiaa: event.eiaa,
            };

        case 'SUBMIT_STEP':
            return { ...state, flowState: 'SUBMITTING' };

        case 'STEP_RESPONSE':
            return {
                ...state,
                flowState: 'RENDER_STEP',
                currentStep: event.uiStep,
                eiaa: { ...state.eiaa, ...event.eiaa },
            };

        case 'DECISION_READY':
            return {
                ...state,
                flowState: 'DECISION_READY',
                decisionRef: event.decisionRef,
                eiaa: { ...state.eiaa, achievedAal: event.achievedAal || state.eiaa.achievedAal },
            };

        case 'NETWORK_ERROR':
            return {
                ...state,
                flowState: 'ERROR_RECOVERABLE',
                errorMessage: event.message,
            };

        case 'RETRY':
            return { ...state, flowState: 'RENDER_STEP', errorMessage: null };

        case 'RESTART':
            return { ...initialState };

        case 'COMMIT_CONFIRMED':
            return { ...state, flowState: 'REDIRECT' };

        default:
            return state;
    }
}

const initialState: State = {
    flowState: 'INIT',
    flowId: null,
    currentStep: null,
    errorMessage: null,
    decisionRef: null,
    eiaa: defaultEiaaContext,
};

// ============================================
// API CLIENT
// ============================================

const API_BASE = '/api/hosted';

async function initFlow(orgId: string, intent: FlowIntent) {
    const url = `${API_BASE}/auth/flows`;
    console.log(`[AuthFlow] Initializing flow: POST ${url}`, { orgId, intent });

    try {
        const res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ org_id: orgId, intent }),
        });

        if (!res.ok) {
            const text = await res.text();
            console.error(`[AuthFlow] Init failed: ${res.status} ${res.statusText}`, text);
            throw new Error(`Failed to init flow: ${res.status} ${res.statusText}`);
        }
        return res.json();
    } catch (e) {
        console.error('[AuthFlow] Network or parsing error:', e);
        throw e;
    }
}

async function submitStep(flowId: string, stepType: string, value: any) {
    const res = await fetch(`${API_BASE}/auth/flows/${flowId}/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: stepType, value }),
    });

    if (!res.ok) {
        // EIAA: Handle session expiration/invalid flow explicitly
        if (res.status === 404) {
            throw new Error('Session expired or flow invalid. Please restart.');
        }

        const text = await res.text();
        try {
            const json = JSON.parse(text);
            throw new Error(json.message || json.error || 'Step submission failed');
        } catch (e) {
            throw new Error(text || `Step submission failed: ${res.status}`);
        }
    }
    return res.json();
}

// ============================================
// EIAA STATUS DISPLAY
// ============================================

function RiskBadge({ level }: { level: string }) {
    const colors = {
        Low: 'bg-green-100 text-green-700 border-green-200',
        Medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
        High: 'bg-red-100 text-red-700 border-red-200',
    };
    const color = colors[level as keyof typeof colors] || colors.Low;

    return (
        <span className={`px-2 py-0.5 text-xs font-medium rounded border ${color}`}>
            {level} Risk
        </span>
    );
}

function AalProgress({ required, achieved }: { required: string; achieved: string | null }) {
    const aalLevels = ['AAL0', 'AAL1', 'AAL2', 'AAL3'];
    const requiredIdx = aalLevels.indexOf(required);
    const achievedIdx = achieved ? aalLevels.indexOf(achieved) : 0;
    const progress = Math.min(100, (achievedIdx / Math.max(requiredIdx, 1)) * 100);

    return (
        <div className="space-y-1">
            <div className="flex justify-between text-xs text-gray-500">
                <span>{achieved || 'AAL0'}</span>
                <span>{required}</span>
            </div>
            <div className="h-1.5 bg-gray-200 rounded-full overflow-hidden">
                <div
                    className={`h-full transition-all duration-300 ${achievedIdx >= requiredIdx ? 'bg-green-500' : 'bg-blue-500'
                        }`}
                    style={{ width: `${progress}%` }}
                />
            </div>
        </div>
    );
}

function EiaaStatusBadge({ eiaa }: { eiaa: EiaaContext }) {
    // Ensure all values have defaults to prevent crashes
    const riskLevel = eiaa?.riskLevel || 'Low';
    const requiredAal = eiaa?.requiredAal || 'AAL1';
    const achievedAal = eiaa?.achievedAal || null;
    const capabilities = eiaa?.acceptableCapabilities || [];

    return (
        <div className="mb-4 p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg border border-gray-200 dark:border-gray-600">
            <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-medium text-gray-500 dark:text-gray-400">Security Status</span>
                <RiskBadge level={riskLevel} />
            </div>
            <AalProgress required={requiredAal} achieved={achievedAal} />
            {capabilities.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1">
                    {capabilities.map(cap => (
                        <span key={cap} className="px-1.5 py-0.5 text-xs bg-blue-50 text-blue-600 rounded">
                            {cap}
                        </span>
                    ))}
                </div>
            )}
        </div>
    );
}


// ============================================
// STEP RENDERERS
// ============================================

interface StepProps {
    step: UiStep;
    onSubmit: (stepType: string, value: any) => void;
    disabled: boolean;
}

function EmailStep({ step, onSubmit, disabled }: StepProps) {
    const [email, setEmail] = React.useState('');
    if (step.type !== 'email') return null;

    return (
        <form onSubmit={(e) => { e.preventDefault(); onSubmit('email', email); }}>
            <label className="block text-sm font-medium text-gray-700 mb-2">
                {step.label}
            </label>
            <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required={step.required}
                disabled={disabled}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                placeholder="you@example.com"
            />
            <button
                type="submit"
                disabled={disabled}
                className="w-full mt-4 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
                Continue
            </button>
        </form>
    );
}

function PasswordStep({ step, onSubmit, disabled }: StepProps) {
    const [password, setPassword] = React.useState('');
    if (step.type !== 'password') return null;

    return (
        <form onSubmit={(e) => { e.preventDefault(); onSubmit('password', password); }}>
            <label className="block text-sm font-medium text-gray-700 mb-2">
                {step.label}
            </label>
            <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                disabled={disabled}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                placeholder="••••••••"
            />
            <button
                type="submit"
                disabled={disabled}
                className="w-full mt-4 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
                Sign In
            </button>
        </form>
    );
}

function OtpStep({ step, onSubmit, disabled }: StepProps) {
    const [otp, setOtp] = React.useState('');
    if (step.type !== 'otp') return null;

    return (
        <form onSubmit={(e) => { e.preventDefault(); onSubmit('otp', otp); }}>
            <label className="block text-sm font-medium text-gray-700 mb-2">
                {step.label}
            </label>
            <input
                type="text"
                value={otp}
                onChange={(e) => setOtp(e.target.value)}
                required
                disabled={disabled}
                maxLength={6}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 text-center text-2xl tracking-widest"
                placeholder="000000"
            />
            <button
                type="submit"
                disabled={disabled}
                className="w-full mt-4 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
                Verify
            </button>
        </form>
    );
}

function CredentialsStep({ step, onSubmit, disabled }: StepProps) {
    const [values, setValues] = React.useState<Record<string, string>>({});
    if (step.type !== 'credentials') return null;

    const handleChange = (name: string, value: string) => {
        setValues(prev => ({ ...prev, [name]: value }));
    };

    return (
        <form onSubmit={(e) => { e.preventDefault(); onSubmit('credentials', values); }}>
            <div className="space-y-4">
                {step.fields.map((field) => (
                    <div key={field.name}>
                        <label className="block text-sm font-medium text-gray-700 mb-2">
                            {field.label}
                            {field.required && <span className="text-red-500 ml-1">*</span>}
                        </label>
                        <input
                            type={field.format === 'password' ? 'password' : field.format === 'email' ? 'email' : 'text'}
                            value={values[field.name] || ''}
                            onChange={(e) => handleChange(field.name, e.target.value)}
                            required={field.required}
                            minLength={field.min_length}
                            disabled={disabled}
                            className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500"
                        />
                    </div>
                ))}
            </div>
            <button
                type="submit"
                disabled={disabled}
                className="w-full mt-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
                Create Account
            </button>
        </form>
    );
}

function EmailVerificationStep({ step, onSubmit, disabled }: StepProps) {
    const [code, setCode] = React.useState('');
    if (step.type !== 'email_verification') return null;

    return (
        <form onSubmit={(e) => { e.preventDefault(); onSubmit('email_verification', code); }}>
            <p className="text-gray-600 mb-4">
                We sent a code to <strong>{step.email}</strong>
            </p>
            <label className="block text-sm font-medium text-gray-700 mb-2">
                {step.label}
            </label>
            <input
                type="text"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                required
                disabled={disabled}
                maxLength={6}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 text-center text-2xl tracking-widest"
                placeholder="000000"
            />
            <button
                type="submit"
                disabled={disabled}
                className="w-full mt-4 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
                Verify Email
            </button>
        </form>
    );
}

// EIAA: Reset Code Verification Step (Credential Recovery)
function ResetCodeStep({ step, onSubmit, disabled }: StepProps) {
    const [code, setCode] = React.useState('');
    if (step.type !== 'reset_code_verification') return null;

    return (
        <form onSubmit={(e) => { e.preventDefault(); onSubmit('reset_code', code); }}>
            <div className="text-center mb-4">
                <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-blue-100 mb-3">
                    <svg className="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                    </svg>
                </div>
                <p className="text-gray-600">
                    We sent a code to <strong>{step.email}</strong>
                </p>
            </div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
                {step.label}
            </label>
            <input
                type="text"
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                required
                disabled={disabled}
                maxLength={6}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 text-center text-2xl tracking-widest"
                placeholder="000000"
                autoComplete="one-time-code"
            />
            <button
                type="submit"
                disabled={disabled || code.length < 6}
                className="w-full mt-4 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
                Verify Code
            </button>
            <p className="text-xs text-gray-500 text-center mt-3">
                Code expires in 10 minutes
            </p>
        </form>
    );
}

// EIAA: New Password Step (Credential Recovery)
function NewPasswordStep({ step, onSubmit, disabled }: StepProps) {
    const [password, setPassword] = React.useState('');
    const [confirmPassword, setConfirmPassword] = React.useState('');
    const [showPassword, setShowPassword] = React.useState(false);
    if (step.type !== 'new_password') return null;

    const passwordsMatch = password === confirmPassword;
    const isValid = password.length >= 8 && passwordsMatch;

    return (
        <form onSubmit={(e) => { e.preventDefault(); if (isValid) onSubmit('new_password', password); }}>
            <div className="text-center mb-4">
                <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-green-100 mb-3">
                    <svg className="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                    </svg>
                </div>
            </div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
                {step.label}
            </label>
            <div className="relative">
                <input
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    disabled={disabled}
                    minLength={8}
                    className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 pr-12"
                    placeholder="New password"
                />
                <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-700"
                >
                    {showPassword ? '🙈' : '👁️'}
                </button>
            </div>
            {step.hint && (
                <p className="text-xs text-gray-500 mt-1">{step.hint}</p>
            )}
            <label className="block text-sm font-medium text-gray-700 mb-2 mt-4">
                Confirm Password
            </label>
            <input
                type={showPassword ? "text" : "password"}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                disabled={disabled}
                className={`w-full px-4 py-3 border rounded-lg focus:ring-2 ${confirmPassword && !passwordsMatch
                    ? 'border-red-300 focus:ring-red-500'
                    : 'border-gray-300 focus:ring-blue-500'
                    }`}
                placeholder="Confirm new password"
            />
            {confirmPassword && !passwordsMatch && (
                <p className="text-xs text-red-500 mt-1">Passwords do not match</p>
            )}
            <button
                type="submit"
                disabled={disabled || !isValid}
                className="w-full mt-4 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
                Reset Password
            </button>
        </form>
    );
}

function StepRenderer({ step, onSubmit, disabled }: StepProps) {
    switch (step.type) {
        case 'email':
            return <EmailStep step={step} onSubmit={onSubmit} disabled={disabled} />;
        case 'password':
            return <PasswordStep step={step} onSubmit={onSubmit} disabled={disabled} />;
        case 'otp':
            return <OtpStep step={step} onSubmit={onSubmit} disabled={disabled} />;
        case 'credentials':
            return <CredentialsStep step={step} onSubmit={onSubmit} disabled={disabled} />;
        case 'email_verification':
            return <EmailVerificationStep step={step} onSubmit={onSubmit} disabled={disabled} />;
        case 'reset_code_verification':
            return <ResetCodeStep step={step} onSubmit={onSubmit} disabled={disabled} />;
        case 'new_password':
            return <NewPasswordStep step={step} onSubmit={onSubmit} disabled={disabled} />;
        case 'error':
            return (
                <div className="p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">
                    {step.message}
                </div>
            );
        default:
            return <div>Unknown step type</div>;
    }
}

// ============================================
// MAIN COMPONENT
// ============================================

interface AuthFlowPageProps {
    intent: FlowIntent;
}

export default function AuthFlowPage({ intent }: AuthFlowPageProps) {
    const { slug } = useParams<{ slug: string }>();
    const navigate = useNavigate();
    const [state, dispatch] = useReducer(flowReducer, initialState);

    // Initialize flow on mount
    useEffect(() => {
        const startFlow = async () => {
            dispatch({ type: 'START_FLOW' });
            try {
                // EIAA: 'admin' slug maps to 'system' org ID (Provider Authority)
                const orgId = slug === 'admin' ? 'system' : (slug || 'default');
                const response = await initFlow(orgId, intent);
                dispatch({
                    type: 'FLOW_CREATED',
                    flowId: response.flow_id,
                    uiStep: response.ui_step,
                    eiaa: {
                        acceptableCapabilities: response.acceptable_capabilities || [],
                        requiredAal: response.required_aal || 'AAL1',
                        achievedAal: null,
                        riskLevel: response.risk_level || 'Low',
                    },
                });
            } catch (error: any) {
                dispatch({ type: 'NETWORK_ERROR', message: error.message });
            }
        };

        startFlow();
    }, [slug, intent]);

    // Handle decision ready
    useEffect(() => {
        if (state.flowState === 'DECISION_READY') {
            const message = intent === 'resetpassword'
                ? 'Password reset successful!'
                : 'Authentication successful!';
            toast.success(message);
            dispatch({ type: 'COMMIT_CONFIRMED' });
        }
    }, [state.flowState, intent]);

    // Redirect after completion
    useEffect(() => {
        if (state.flowState === 'REDIRECT') {
            // Password reset redirects to login
            if (intent === 'resetpassword') {
                navigate(`/u/${slug || 'default'}`);
            } else if (intent === 'login' || intent === 'signup') {
                // EIAA: Context-aware redirection
                if (slug === 'admin') {
                    navigate('/admin/dashboard');
                } else {
                    navigate('/dashboard');
                }
            }
        }
    }, [state.flowState, intent, navigate, slug]);

    // ... (handlers)

    // Helper to determine display title
    const getPageTitle = () => {
        if (slug === 'admin') return 'Provider Admin Portal';
        if (state.eiaa.orgName) return `Sign in to ${state.eiaa.orgName}`;
        return intent === 'login' ? 'Sign In' : intent === 'signup' ? 'Create Account' : 'Reset Password';
    };

    const getPageSubtitle = () => {
        if (slug === 'admin') return 'Authorized Personnel Only';
        if (intent === 'login') return 'Welcome back';
        if (intent === 'signup') return 'Get started today';
        return 'Enter your email to reset your password';
    };

    const handleSubmit = async (stepType: string, value: any) => {
        if (!state.flowId) return;
        dispatch({ type: 'SUBMIT_STEP' });
        try {
            const res = await submitStep(state.flowId, stepType, value);
            if (res.ui_step) {
                dispatch({
                    type: 'STEP_RESPONSE',
                    uiStep: res.ui_step,
                    eiaa: {
                        achievedAal: res.achieved_aal,
                        acceptableCapabilities: res.acceptable_capabilities,
                    }
                });
            } else if (res.decision_ref) {
                // EIAA: Store session token if provided
                if (res.token) {
                    sessionStorage.setItem('jwt', res.token);

                    // EIAA: Store active org context to ensure API client sends correct header
                    // Maps URL slug to Internal ID: 'admin' slug -> 'system' ID
                    const contextId = slug === 'admin' ? 'system' : (slug || 'default');
                    sessionStorage.setItem('active_org_id', contextId);
                }

                dispatch({
                    type: 'DECISION_READY',
                    decisionRef: res.decision_ref,
                    achievedAal: res.achieved_aal,
                });
            }
        } catch (err: any) {
            dispatch({ type: 'NETWORK_ERROR', message: err.message });
        }
    };

    const renderContent = () => {
        if (state.flowState === 'INIT' || state.flowState === 'FLOW_INIT') {
            return (
                <div className="flex justify-center py-12">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
                </div>
            );
        }

        if (state.flowState === 'ERROR_FATAL') {
            return (
                <div className="p-4 bg-red-50 text-red-700 rounded-lg">
                    <h3 className="font-bold">System Error</h3>
                    <p>{state.errorMessage || 'An unexpected error occurred.'}</p>
                    <button
                        onClick={() => window.location.reload()}
                        className="mt-4 px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700"
                    >
                        Reload Page
                    </button>
                </div>
            );
        }

        return (
            <div className="space-y-6">
                {state.errorMessage && (
                    <div className="p-4 bg-red-50 text-red-700 rounded-lg text-sm mb-4 border border-red-200">
                        <div className="font-medium mb-1">Error</div>
                        <p>{state.errorMessage}</p>
                        {(state.errorMessage.toLowerCase().includes('restart') || state.errorMessage.toLowerCase().includes('expired')) && (
                            <button
                                onClick={() => window.location.reload()}
                                className="mt-2 px-3 py-1.5 bg-red-100 text-red-800 rounded hover:bg-red-200 text-xs font-medium transition-colors"
                            >
                                Restart Session
                            </button>
                        )}
                    </div>
                )}

                <EiaaStatusBadge eiaa={state.eiaa} />

                {state.currentStep && (
                    <StepRenderer
                        step={state.currentStep}
                        onSubmit={handleSubmit}
                        disabled={state.flowState === 'SUBMITTING'}
                    />
                )}
            </div>
        );
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-purple-100 dark:from-gray-900 dark:to-gray-800"
            style={state.eiaa.branding?.primary_color ? {
                '--primary-color': state.eiaa.branding.primary_color
            } as React.CSSProperties : {}}>
            <div className="w-full max-w-md p-8 bg-white dark:bg-gray-800 rounded-xl shadow-xl">
                <div className="text-center mb-8">
                    <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
                        {getPageTitle()}
                    </h1>
                    <p className="text-gray-600 dark:text-gray-400 mt-2">
                        {getPageSubtitle()}
                    </p>
                </div>

                {renderContent()}

                <div className="mt-6 text-center space-y-2">
                    {intent === 'login' && (
                        <a
                            href={`/u/${slug || 'default'}/reset-password`}
                            className="text-sm text-gray-500 hover:text-blue-600 hover:underline block"
                        >
                            Forgot your password?
                        </a>
                    )}
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                        {intent === 'login' ? (
                            <>Don't have an account? <a href={`/u/${slug || 'default'}/signup`} className="text-blue-600 hover:underline">Sign up</a></>
                        ) : intent === 'signup' ? (
                            <>Already have an account? <a href={`/u/${slug || 'default'}`} className="text-blue-600 hover:underline">Sign in</a></>
                        ) : (
                            <>Remember your password? <a href={`/u/${slug || 'default'}`} className="text-blue-600 hover:underline">Sign in</a></>
                        )}
                    </p>
                </div>
            </div>
        </div>
    );
}
