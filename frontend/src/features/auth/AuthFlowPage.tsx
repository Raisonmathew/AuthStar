/**
 * EIAA-Compliant Auth Flow Page
 *
 * This is a UNIVERSAL flow renderer. It:
 * - Renders EXACTLY what the backend tells it
 * - Never makes security decisions
 * - Never validates meaning
 * - Operates as a deterministic FSM
 */

import React, { useReducer, useEffect, useCallback, useId } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { toast } from 'sonner';
import { useAuth } from './AuthContext';
import { signupFlowsApi } from '../../lib/api/signupFlows';
// E-3: react-hook-form + zod for client-side validation with accessible error messages
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';

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
    flowToken: string | null;  // GAP-5: Ephemeral flow token from init_flow
    currentStep: UiStep | null;
    errorMessage: string | null;
    decisionRef: string | null;
    eiaa: EiaaContext;
}

type FlowEvent =
    | { type: 'START_FLOW' }
    | { type: 'FLOW_CREATED'; flowId: string; flowToken: string; uiStep: UiStep; eiaa: EiaaContext }
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
                flowToken: event.flowToken,  // GAP-5: Store ephemeral token
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
    flowToken: null,
    currentStep: null,
    errorMessage: null,
    decisionRef: null,
    eiaa: defaultEiaaContext,
};

// ============================================
// API CLIENT
// ============================================

// GAP-4 FIX (BUG-11): Correct base path for the secured EIAA flow engine.
// Previously used `/api/hosted` which routes to the deprecated hosted flow
// engine. The backend's EIAA-secured flow engine lives at `/api/auth/flow`.
const API_BASE = '/api/auth/flow';

async function initFlow(orgId: string, intent: FlowIntent) {
    const url = `${API_BASE}/init`;
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

// C-1: Sentinel error class for FLOW_EXPIRED (HTTP 410 Gone).
// handleSubmit detects this and auto-restarts the flow rather than showing
// a generic error message.
class FlowExpiredError extends Error {
    constructor() {
        super('Your login session has expired. Starting a new session…');
        this.name = 'FlowExpiredError';
    }
}

/**
 * GAP-6 FIX (BUG-13): Identify the user by email/username.
 * This is a SEPARATE endpoint from /submit — it triggers risk re-evaluation
 * and returns the next set of capabilities the user must prove.
 * Previously the frontend incorrectly used submitStep for email identification.
 */
async function identifyUser(flowId: string, identifier: string, flowToken: string) {
    const res = await fetch(`${API_BASE}/${flowId}/identify`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            // GAP-5 FIX (BUG-12): Attach ephemeral flow_token as Bearer auth.
            'Authorization': `Bearer ${flowToken}`,
        },
        body: JSON.stringify({ identifier }),
    });

    if (!res.ok) {
        if (res.status === 410) throw new FlowExpiredError();
        if (res.status === 404) throw new Error('Session expired or flow invalid. Please restart.');
        const text = await res.text();
        try {
            const json = JSON.parse(text);
            throw new Error(json.message || json.error || 'User identification failed');
        } catch (e) {
            throw new Error(text || `Identification failed: ${res.status}`);
        }
    }
    return res.json();
}

/**
 * GAP-5 FIX (BUG-12): Submit a credential step with flow_token Bearer auth.
 * The backend validates this token with SHA-256 + constant-time comparison.
 */
async function submitStep(flowId: string, stepType: string, value: any, flowToken: string) {
    const res = await fetch(`${API_BASE}/${flowId}/submit`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${flowToken}`,
        },
        body: JSON.stringify({ type: stepType, value }),
    });

    if (!res.ok) {
        // C-1: 410 Gone = FLOW_EXPIRED — throw sentinel so handleSubmit can restart
        if (res.status === 410) {
            throw new FlowExpiredError();
        }
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

// ─── Zod Schemas ─────────────────────────────────────────────────────────────
// E-3: Client-side validation schemas. These are intentionally lenient —
// the backend is the authoritative validator. The purpose here is to give
// immediate, accessible feedback before the network round-trip.

const emailSchema = z.object({
    email: z
        .string()
        .min(1, 'Email is required')
        .email('Please enter a valid email address'),
});

const passwordSchema = z.object({
    password: z
        .string()
        .min(1, 'Password is required')
        .min(8, 'Password must be at least 8 characters'),
});

const otpSchema = z.object({
    otp: z
        .string()
        .min(1, 'Verification code is required')
        .length(6, 'Code must be exactly 6 digits')
        .regex(/^\d{6}$/, 'Code must contain only digits'),
});

// ─── Shared field error component ────────────────────────────────────────────
// E-4: role="alert" + aria-live="polite" so screen readers announce errors
// as soon as they appear without interrupting the user's current focus.
function FieldError({ id, message }: { id: string; message?: string }) {
    if (!message) return null;
    return (
        <p
            id={id}
            role="alert"
            aria-live="polite"
            className="mt-1 text-sm text-red-600"
        >
            {message}
        </p>
    );
}

// ─── EmailStep ────────────────────────────────────────────────────────────────
// E-3 + E-4: react-hook-form + zod validation + ARIA labels
function EmailStep({ step, onSubmit, disabled }: StepProps) {
    const inputId = useId();
    const errorId = `${inputId}-error`;

    const {
        register,
        handleSubmit,
        formState: { errors },
    } = useForm<z.infer<typeof emailSchema>>({
        resolver: zodResolver(emailSchema),
    });

    if (step.type !== 'email') return null;

    return (
        <form
            onSubmit={handleSubmit(({ email }) => onSubmit('email', email))}
            noValidate
            aria-label="Email address form"
        >
            <div>
                <label
                    htmlFor={inputId}
                    className="block text-sm font-medium text-gray-700 mb-2"
                >
                    {step.label}
                </label>
                <input
                    id={inputId}
                    type="email"
                    autoComplete="email"
                    disabled={disabled}
                    aria-required="true"
                    aria-invalid={!!errors.email}
                    aria-describedby={errors.email ? errorId : undefined}
                    className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-blue-500 ${errors.email ? 'border-red-500' : 'border-gray-300'
                        }`}
                    placeholder="you@example.com"
                    {...register('email')}
                />
                <FieldError id={errorId} message={errors.email?.message} />
            </div>
            <button
                type="submit"
                disabled={disabled}
                aria-busy={disabled}
                className="w-full mt-4 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
                Continue
            </button>
        </form>
    );
}

// ─── PasswordStep ─────────────────────────────────────────────────────────────
// E-3 + E-4: react-hook-form + zod validation + ARIA labels
function PasswordStep({ step, onSubmit, disabled }: StepProps) {
    const inputId = useId();
    const errorId = `${inputId}-error`;

    const {
        register,
        handleSubmit,
        formState: { errors },
    } = useForm<z.infer<typeof passwordSchema>>({
        resolver: zodResolver(passwordSchema),
    });

    if (step.type !== 'password') return null;

    return (
        <form
            onSubmit={handleSubmit(({ password }) => onSubmit('password', password))}
            noValidate
            aria-label="Password form"
        >
            <div>
                <label
                    htmlFor={inputId}
                    className="block text-sm font-medium text-gray-700 mb-2"
                >
                    {step.label}
                </label>
                <input
                    id={inputId}
                    type="password"
                    autoComplete="current-password"
                    disabled={disabled}
                    aria-required="true"
                    aria-invalid={!!errors.password}
                    aria-describedby={errors.password ? errorId : undefined}
                    className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-blue-500 ${errors.password ? 'border-red-500' : 'border-gray-300'
                        }`}
                    placeholder="••••••••"
                    {...register('password')}
                />
                <FieldError id={errorId} message={errors.password?.message} />
            </div>
            <button
                type="submit"
                disabled={disabled}
                aria-busy={disabled}
                className="w-full mt-4 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
                Sign In
            </button>
        </form>
    );
}

// ─── OtpStep ──────────────────────────────────────────────────────────────────
// E-3 + E-4: react-hook-form + zod validation + ARIA labels
function OtpStep({ step, onSubmit, disabled }: StepProps) {
    const inputId = useId();
    const errorId = `${inputId}-error`;

    const {
        register,
        handleSubmit,
        formState: { errors },
    } = useForm<z.infer<typeof otpSchema>>({
        resolver: zodResolver(otpSchema),
    });

    if (step.type !== 'otp') return null;

    return (
        <form
            onSubmit={handleSubmit(({ otp }) => onSubmit('otp', otp))}
            noValidate
            aria-label="One-time code verification form"
        >
            <div>
                <label
                    htmlFor={inputId}
                    className="block text-sm font-medium text-gray-700 mb-2"
                >
                    {step.label}
                </label>
                <input
                    id={inputId}
                    type="text"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    maxLength={6}
                    disabled={disabled}
                    aria-required="true"
                    aria-invalid={!!errors.otp}
                    aria-describedby={errors.otp ? errorId : undefined}
                    className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-blue-500 text-center text-2xl tracking-widest ${errors.otp ? 'border-red-500' : 'border-gray-300'
                        }`}
                    placeholder="000000"
                    {...register('otp')}
                />
                <FieldError id={errorId} message={errors.otp?.message} />
            </div>
            <button
                type="submit"
                disabled={disabled}
                aria-busy={disabled}
                className="w-full mt-4 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
                Verify
            </button>
        </form>
    );
}

// ─── CredentialsStep ──────────────────────────────────────────────────────────
// E-3 + E-4: Dynamic fields from server schema — build a zod schema at render
// time from the field definitions, then use react-hook-form with that schema.
// Each field gets a stable id, aria-required, aria-invalid, and aria-describedby.
function CredentialsStep({ step, onSubmit, disabled }: StepProps) {
    if (step.type !== 'credentials') return null;

    // Build a zod object schema dynamically from the server-provided field list.
    // This runs once per mount (fields are stable for the lifetime of the step).
    const schema = React.useMemo(() => {
        const shape: Record<string, z.ZodTypeAny> = {};
        for (const field of step.fields) {
            let s: z.ZodString = z.string();
            if (field.required) {
                s = s.min(1, `${field.label} is required`);
            }
            if (field.min_length && field.min_length > 0) {
                s = s.min(field.min_length, `${field.label} must be at least ${field.min_length} characters`);
            }
            if (field.format === 'email') {
                s = s.email(`${field.label} must be a valid email address`);
            }
            shape[field.name] = field.required ? s : s.optional();
        }
        return z.object(shape);
    }, []); // eslint-disable-line react-hooks/exhaustive-deps

    const {
        register,
        handleSubmit,
        formState: { errors },
    } = useForm<Record<string, string>>({
        resolver: zodResolver(schema),
    });

    return (
        <form
            onSubmit={handleSubmit((values) => onSubmit('credentials', values))}
            noValidate
            aria-label="Account registration form"
        >
            <div className="space-y-4">
                {step.fields.map((field) => {
                    const fieldError = errors[field.name];
                    const inputId = `credentials-${field.name}`;
                    const errorId = `${inputId}-error`;
                    return (
                        <div key={field.name}>
                            <label
                                htmlFor={inputId}
                                className="block text-sm font-medium text-gray-700 mb-2"
                            >
                                {field.label}
                                {field.required && (
                                    <span className="text-red-500 ml-1" aria-hidden="true">*</span>
                                )}
                            </label>
                            <input
                                id={inputId}
                                type={
                                    field.format === 'password'
                                        ? 'password'
                                        : field.format === 'email'
                                            ? 'email'
                                            : 'text'
                                }
                                autoComplete={
                                    field.format === 'password'
                                        ? 'new-password'
                                        : field.format === 'email'
                                            ? 'email'
                                            : 'off'
                                }
                                disabled={disabled}
                                aria-required={field.required}
                                aria-invalid={!!fieldError}
                                aria-describedby={fieldError ? errorId : undefined}
                                className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-blue-500 ${fieldError ? 'border-red-500' : 'border-gray-300'
                                    }`}
                                {...register(field.name)}
                            />
                            <FieldError id={errorId} message={fieldError?.message as string | undefined} />
                        </div>
                    );
                })}
            </div>
            <button
                type="submit"
                disabled={disabled}
                aria-busy={disabled}
                className="w-full mt-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
                Create Account
            </button>
        </form>
    );
}

// ─── EmailVerificationStep ────────────────────────────────────────────────────
// E-3 + E-4: Same OTP schema as OtpStep — 6 numeric digits
function EmailVerificationStep({ step, onSubmit, disabled }: StepProps) {
    const inputId = useId();
    const errorId = `${inputId}-error`;

    const {
        register,
        handleSubmit,
        formState: { errors },
    } = useForm<z.infer<typeof otpSchema>>({
        resolver: zodResolver(otpSchema),
    });

    if (step.type !== 'email_verification') return null;

    return (
        <form
            onSubmit={handleSubmit(({ otp }) => onSubmit('email_verification', otp))}
            noValidate
            aria-label="Email verification form"
        >
            <p className="text-gray-600 mb-4">
                We sent a code to <strong>{step.email}</strong>
            </p>
            <div>
                <label
                    htmlFor={inputId}
                    className="block text-sm font-medium text-gray-700 mb-2"
                >
                    {step.label}
                </label>
                <input
                    id={inputId}
                    type="text"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    maxLength={6}
                    disabled={disabled}
                    aria-required="true"
                    aria-invalid={!!errors.otp}
                    aria-describedby={errors.otp ? errorId : undefined}
                    className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-blue-500 text-center text-2xl tracking-widest ${errors.otp ? 'border-red-500' : 'border-gray-300'
                        }`}
                    placeholder="000000"
                    {...register('otp')}
                />
                <FieldError id={errorId} message={errors.otp?.message} />
            </div>
            <button
                type="submit"
                disabled={disabled}
                aria-busy={disabled}
                className="w-full mt-4 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
                Verify Email
            </button>
        </form>
    );
}

// ─── ResetCodeStep ────────────────────────────────────────────────────────────
// EIAA: Reset Code Verification Step (Credential Recovery)
// E-3 + E-4: Same OTP schema — 6 numeric digits + ARIA
function ResetCodeStep({ step, onSubmit, disabled }: StepProps) {
    const inputId = useId();
    const errorId = `${inputId}-error`;

    const {
        register,
        handleSubmit,
        watch,
        formState: { errors },
    } = useForm<z.infer<typeof otpSchema>>({
        resolver: zodResolver(otpSchema),
    });

    const currentOtp = watch('otp', '');

    if (step.type !== 'reset_code_verification') return null;

    return (
        <form
            onSubmit={handleSubmit(({ otp }) => onSubmit('reset_code', otp))}
            noValidate
            aria-label="Password reset code verification form"
        >
            <div className="text-center mb-4">
                <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-blue-100 mb-3">
                    <svg className="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                    </svg>
                </div>
                <p className="text-gray-600">
                    We sent a code to <strong>{step.email}</strong>
                </p>
            </div>
            <div>
                <label
                    htmlFor={inputId}
                    className="block text-sm font-medium text-gray-700 mb-2"
                >
                    {step.label}
                </label>
                <input
                    id={inputId}
                    type="text"
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    maxLength={6}
                    disabled={disabled}
                    aria-required="true"
                    aria-invalid={!!errors.otp}
                    aria-describedby={errors.otp ? errorId : undefined}
                    className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-blue-500 text-center text-2xl tracking-widest ${errors.otp ? 'border-red-500' : 'border-gray-300'
                        }`}
                    placeholder="000000"
                    {...register('otp')}
                />
                <FieldError id={errorId} message={errors.otp?.message} />
            </div>
            <button
                type="submit"
                disabled={disabled || currentOtp.length < 6}
                aria-busy={disabled}
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
// ─── NewPasswordStep ──────────────────────────────────────────────────────────
// E-3 + E-4: zod superRefine for password-match cross-field validation + ARIA.
// The show/hide toggle is preserved; it switches both inputs simultaneously.
const newPasswordSchema = z
    .object({
        password: z
            .string()
            .min(1, 'Password is required')
            .min(8, 'Password must be at least 8 characters'),
        confirmPassword: z
            .string()
            .min(1, 'Please confirm your password'),
    })
    .superRefine(({ password, confirmPassword }, ctx) => {
        if (password !== confirmPassword) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'Passwords do not match',
                path: ['confirmPassword'],
            });
        }
    });

function NewPasswordStep({ step, onSubmit, disabled }: StepProps) {
    const [showPassword, setShowPassword] = React.useState(false);
    const passwordId = useId();
    const confirmId = useId();
    const passwordErrorId = `${passwordId}-error`;
    const confirmErrorId = `${confirmId}-error`;
    const hintId = `${passwordId}-hint`;

    const {
        register,
        handleSubmit,
        formState: { errors },
    } = useForm<z.infer<typeof newPasswordSchema>>({
        resolver: zodResolver(newPasswordSchema),
    });

    if (step.type !== 'new_password') return null;

    return (
        <form
            onSubmit={handleSubmit(({ password }) => onSubmit('new_password', password))}
            noValidate
            aria-label="Set new password form"
        >
            <div className="text-center mb-4">
                <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-green-100 mb-3">
                    <svg className="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                    </svg>
                </div>
            </div>

            {/* New password field */}
            <div>
                <label
                    htmlFor={passwordId}
                    className="block text-sm font-medium text-gray-700 mb-2"
                >
                    {step.label}
                </label>
                <div className="relative">
                    <input
                        id={passwordId}
                        type={showPassword ? 'text' : 'password'}
                        autoComplete="new-password"
                        disabled={disabled}
                        aria-required="true"
                        aria-invalid={!!errors.password}
                        aria-describedby={[
                            errors.password ? passwordErrorId : '',
                            step.hint ? hintId : '',
                        ].filter(Boolean).join(' ') || undefined}
                        className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-blue-500 pr-12 ${errors.password ? 'border-red-500' : 'border-gray-300'
                            }`}
                        placeholder="New password"
                        {...register('password')}
                    />
                    <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        aria-label={showPassword ? 'Hide password' : 'Show password'}
                        aria-pressed={showPassword}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-700"
                    >
                        {showPassword ? '🙈' : '👁️'}
                    </button>
                </div>
                <FieldError id={passwordErrorId} message={errors.password?.message} />
                {step.hint && (
                    <p id={hintId} className="text-xs text-gray-500 mt-1">{step.hint}</p>
                )}
            </div>

            {/* Confirm password field */}
            <div className="mt-4">
                <label
                    htmlFor={confirmId}
                    className="block text-sm font-medium text-gray-700 mb-2"
                >
                    Confirm Password
                </label>
                <input
                    id={confirmId}
                    type={showPassword ? 'text' : 'password'}
                    autoComplete="new-password"
                    disabled={disabled}
                    aria-required="true"
                    aria-invalid={!!errors.confirmPassword}
                    aria-describedby={errors.confirmPassword ? confirmErrorId : undefined}
                    className={`w-full px-4 py-3 border rounded-lg focus:ring-2 focus:ring-blue-500 ${errors.confirmPassword ? 'border-red-500' : 'border-gray-300'
                        }`}
                    placeholder="Confirm new password"
                    {...register('confirmPassword')}
                />
                <FieldError id={confirmErrorId} message={errors.confirmPassword?.message} />
            </div>

            <button
                type="submit"
                disabled={disabled}
                aria-busy={disabled}
                className="w-full mt-4 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
                Reset Password
            </button>
        </form>
    );
}

// ============================================
// FACTOR CHOICE STEP (HIGH-11)
// Renders when backend offers multiple MFA options
// ============================================

function FactorChoiceStep({ step, onSubmit, disabled }: StepProps) {
    if (step.type !== 'factor_choice') return null;

    const iconForFactor = (type: string) => {
        switch (type) {
            case 'totp': return (
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                        d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
            );
            case 'passkey': return (
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                        d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                </svg>
            );
            case 'backup_code': return (
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                        d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
            );
            default: return (
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                        d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
            );
        }
    };

    return (
        <div className="space-y-3">
            <p className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-4">
                Choose a verification method:
            </p>
            {step.options.map((option) => (
                <button
                    key={option.type}
                    type="button"
                    disabled={disabled}
                    onClick={() => onSubmit('factor_choice', option.type)}
                    className="w-full flex items-center gap-3 px-4 py-3 border border-gray-200 dark:border-gray-600 rounded-lg hover:border-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20 transition-colors disabled:opacity-50 text-left"
                >
                    <span className="flex-shrink-0 text-blue-600 dark:text-blue-400">
                        {iconForFactor(option.type)}
                    </span>
                    <span className="text-sm font-medium text-gray-800 dark:text-gray-200">
                        {option.label}
                    </span>
                    <svg className="w-4 h-4 ml-auto text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                    </svg>
                </button>
            ))}
        </div>
    );
}

// ============================================
// PASSKEY CHALLENGE STEP (HIGH-12)
// Renders when backend sends a WebAuthn challenge
// Uses the WebAuthn browser API to sign the challenge
// ============================================

function PasskeyChallengeStep({ step, onSubmit, disabled }: StepProps) {
    const [status, setStatus] = React.useState<'idle' | 'waiting' | 'error'>('idle');
    const [errorMsg, setErrorMsg] = React.useState<string | null>(null);
    if (step.type !== 'passkey_challenge') return null;

    const handlePasskeyAuth = async () => {
        setStatus('waiting');
        setErrorMsg(null);
        try {
            // Convert the backend options to the format expected by the WebAuthn API
            const options = step.options as PublicKeyCredentialRequestOptionsJSON;

            // Decode challenge from base64url
            const challengeBytes = base64urlToUint8Array(options.challenge as unknown as string);

            const allowCredentials = (options.allowCredentials || []).map((cred: any) => ({
                ...cred,
                id: base64urlToUint8Array(cred.id),
            }));

            const publicKeyOptions: PublicKeyCredentialRequestOptions = {
                challenge: challengeBytes as unknown as BufferSource,
                rpId: options.rpId,
                timeout: options.timeout ?? 60000,
                userVerification: (options.userVerification as UserVerificationRequirement) ?? 'preferred',
                allowCredentials,
            };

            const credential = await navigator.credentials.get({
                publicKey: publicKeyOptions,
            }) as PublicKeyCredential | null;

            if (!credential) {
                throw new Error('No credential returned from authenticator');
            }

            const response = credential.response as AuthenticatorAssertionResponse;

            // Serialize for backend
            const serialized = {
                id: credential.id,
                rawId: uint8ArrayToBase64url(new Uint8Array(credential.rawId)),
                type: credential.type,
                response: {
                    authenticatorData: uint8ArrayToBase64url(new Uint8Array(response.authenticatorData)),
                    clientDataJSON: uint8ArrayToBase64url(new Uint8Array(response.clientDataJSON)),
                    signature: uint8ArrayToBase64url(new Uint8Array(response.signature)),
                    userHandle: response.userHandle
                        ? uint8ArrayToBase64url(new Uint8Array(response.userHandle))
                        : null,
                },
            };

            onSubmit('passkey_response', { session_id: step.session_id, credential: serialized });
            setStatus('idle');
        } catch (err: any) {
            setStatus('error');
            if (err.name === 'NotAllowedError') {
                setErrorMsg('Authentication was cancelled or timed out. Please try again.');
            } else if (err.name === 'SecurityError') {
                setErrorMsg('Security error: ensure you are on the correct domain.');
            } else {
                setErrorMsg(err.message || 'Passkey authentication failed');
            }
        }
    };

    return (
        <div className="space-y-4">
            <div className="text-center">
                <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-blue-100 dark:bg-blue-900/30 mb-4">
                    <svg className="w-8 h-8 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                            d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                    </svg>
                </div>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                    {status === 'waiting'
                        ? 'Waiting for your authenticator…'
                        : 'Use your passkey to verify your identity'}
                </p>
            </div>

            {errorMsg && (
                <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">
                    {errorMsg}
                </div>
            )}

            <button
                type="button"
                disabled={disabled || status === 'waiting'}
                onClick={handlePasskeyAuth}
                className="w-full flex items-center justify-center gap-2 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
            >
                {status === 'waiting' ? (
                    <>
                        <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white" />
                        Waiting for authenticator…
                    </>
                ) : (
                    <>
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                                d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                        </svg>
                        Authenticate with Passkey
                    </>
                )}
            </button>
        </div>
    );
}

// ============================================
// BASE64URL HELPERS (for WebAuthn)
// ============================================

function base64urlToUint8Array(base64url: string): Uint8Array {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
    const binary = atob(padded);
    return Uint8Array.from(binary, c => c.charCodeAt(0));
}

function uint8ArrayToBase64url(bytes: Uint8Array): string {
    let binary = '';
    bytes.forEach(b => binary += String.fromCharCode(b));
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// Minimal type for WebAuthn options JSON from backend
interface PublicKeyCredentialRequestOptionsJSON {
    challenge: string;
    rpId?: string;
    timeout?: number;
    userVerification?: string;
    allowCredentials?: Array<{ id: string; type: string; transports?: string[] }>;
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
        case 'factor_choice':
            return <FactorChoiceStep step={step} onSubmit={onSubmit} disabled={disabled} />;
        case 'passkey_challenge':
            return <PasskeyChallengeStep step={step} onSubmit={onSubmit} disabled={disabled} />;
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
    // Use in-memory auth context instead of sessionStorage (CRITICAL-10+11 fix)
    const { setAuth } = useAuth();

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
                    flowToken: response.flow_token,  // GAP-5: capture ephemeral token
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

    // B-2: Handle decision ready.
    //
    // For signup flows, the backend returns a `decision_ref` after the verification
    // code is accepted. The frontend MUST call `commitDecision` to actually create
    // the user account — without this call the user is verified but no account exists.
    //
    // For login/resetpassword flows, the JWT is already set by handleSubmit so we
    // just show a success toast and advance the FSM.
    useEffect(() => {
        if (state.flowState !== 'DECISION_READY') return;

        const handleDecisionReady = async () => {
            if (intent === 'signup' && state.decisionRef && state.flowId) {
                try {
                    // Call commitDecision to create the user account.
                    // The backend verifies that flow_id matches the decision_ref to
                    // prevent replay attacks (FIX-FUNC-4).
                    await signupFlowsApi.commitDecision(state.decisionRef, state.flowId);
                    toast.success('Account created! Welcome aboard.');
                } catch (err: any) {
                    // commitDecision failure is non-fatal for the FSM — the user
                    // is already verified. Show an error but still advance so they
                    // can retry from the dashboard if needed.
                    const msg = err?.response?.data?.message || err?.message || 'Account creation failed';
                    toast.error(`Signup error: ${msg}`);
                }
            } else if (intent === 'resetpassword') {
                toast.success('Password reset successful!');
            } else {
                toast.success('Authentication successful!');
            }
            dispatch({ type: 'COMMIT_CONFIRMED' });
        };

        handleDecisionReady();
    }, [state.flowState, state.decisionRef, state.flowId, intent]);

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

    const handleSubmit = useCallback(async (stepType: string, value: any) => {
        if (!state.flowId || !state.flowToken) return;
        dispatch({ type: 'SUBMIT_STEP' });
        try {
            // GAP-6 FIX (BUG-13): Route email identification through the
            // /identify endpoint, not /submit. The backend expects this to
            // trigger risk re-evaluation after user identification.
            let res;
            if (stepType === 'email') {
                res = await identifyUser(state.flowId, value, state.flowToken);
            } else {
                res = await submitStep(state.flowId, stepType, value, state.flowToken);
            }
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
                // FIX-FUNC-5: Backend complete_flow() returns `jwt` (not `token`).
                // Previously `res.token` was always undefined so setAuth() was never
                // called — users could not log in via the EIAA flow engine.
                if (res.jwt) {
                    if (res.user) {
                        // Backend returned full UserResponse — use it directly.
                        // This ensures mfa_enabled, email_verified, phone, etc.
                        // are correct from the first render after login.
                        setAuth(res.jwt, res.user);
                    } else {
                        // Fallback: construct minimal User (e.g. legacy hosted flow)
                        const orgId = slug === 'admin' ? 'system' : (slug || 'default');
                        setAuth(res.jwt, {
                            id: res.user_id ?? '',
                            email: res.email ?? null,
                            first_name: null,
                            last_name: null,
                            profile_image_url: null,
                            organization_id: orgId,
                            created_at: new Date().toISOString(),
                            email_verified: false,
                            phone: null,
                            phone_verified: false,
                            mfa_enabled: false,
                        });
                    }
                }

                dispatch({
                    type: 'DECISION_READY',
                    decisionRef: res.decision_ref,
                    achievedAal: res.achieved_aal,
                });
            }
        } catch (err: any) {
            // C-1: Flow expired → auto-restart the flow so the user doesn't see
            // a dead error screen. Show a toast so they know what happened.
            if (err instanceof FlowExpiredError) {
                toast.error('Your session expired. Starting a new login…');
                const orgId = slug === 'admin' ? 'system' : (slug || 'default');
                dispatch({ type: 'START_FLOW' });
                try {
                    const response = await initFlow(orgId, intent);
                    dispatch({
                        type: 'FLOW_CREATED',
                        flowId: response.flow_id,
                        flowToken: response.flow_token,  // GAP-5: capture new token on restart
                        uiStep: response.ui_step,
                        eiaa: {
                            acceptableCapabilities: response.acceptable_capabilities || [],
                            requiredAal: response.required_aal || 'AAL1',
                            achievedAal: null,
                            riskLevel: response.risk_level || 'Low',
                        },
                    });
                } catch (restartErr: any) {
                    dispatch({ type: 'NETWORK_ERROR', message: restartErr.message });
                }
                return;
            }
            dispatch({ type: 'NETWORK_ERROR', message: err.message });
        }
    }, [state.flowId, state.flowToken, slug, intent, setAuth]);

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

    // E-5: Mobile-responsive outer shell.
    // - `min-h-screen` + `py-8 px-4` ensures the card never clips on small viewports.
    // - `w-full max-w-md` is already fluid; `sm:rounded-xl` removes border-radius on
    //   very small screens where the card fills the full width.
    // - `p-6 sm:p-8` reduces padding on mobile (375px) to avoid cramped layout.
    // - `text-2xl sm:text-3xl` scales the heading down on small screens.
    // - All interactive elements (buttons, links) already have `w-full py-3` which
    //   satisfies the WCAG 2.5.5 minimum 44px touch target requirement.
    return (
        <div
            className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-purple-100 dark:from-gray-900 dark:to-gray-800 py-8 px-4 sm:px-6"
            style={state.eiaa.branding?.primary_color ? {
                '--primary-color': state.eiaa.branding.primary_color
            } as React.CSSProperties : {}}
        >
            {/* E-5: Card is full-width on mobile, capped at md on larger screens */}
            <div className="w-full max-w-md p-6 sm:p-8 bg-white dark:bg-gray-800 rounded-xl shadow-xl">
                <div className="text-center mb-6 sm:mb-8">
                    <h1 className="text-2xl sm:text-3xl font-bold text-gray-900 dark:text-white">
                        {getPageTitle()}
                    </h1>
                    <p className="text-gray-600 dark:text-gray-400 mt-2 text-sm sm:text-base">
                        {getPageSubtitle()}
                    </p>
                </div>

                {renderContent()}

                {/* E-5: Footer links — min-height 44px via py-3 for touch targets */}
                <div className="mt-6 text-center space-y-2">
                    {intent === 'login' && (
                        <a
                            href={`/u/${slug || 'default'}/reset-password`}
                            className="text-sm text-gray-500 hover:text-blue-600 hover:underline block py-1 min-h-[44px] flex items-center justify-center"
                        >
                            Forgot your password?
                        </a>
                    )}
                    <p className="text-sm text-gray-600 dark:text-gray-400 py-1">
                        {intent === 'login' ? (
                            <>Don't have an account?{' '}
                                <a href={`/u/${slug || 'default'}/signup`} className="text-blue-600 hover:underline font-medium">
                                    Sign up
                                </a>
                            </>
                        ) : intent === 'signup' ? (
                            <>Already have an account?{' '}
                                <a href={`/u/${slug || 'default'}`} className="text-blue-600 hover:underline font-medium">
                                    Sign in
                                </a>
                            </>
                        ) : (
                            <>Remember your password?{' '}
                                <a href={`/u/${slug || 'default'}`} className="text-blue-600 hover:underline font-medium">
                                    Sign in
                                </a>
                            </>
                        )}
                    </p>
                </div>
            </div>
        </div>
    );
}
