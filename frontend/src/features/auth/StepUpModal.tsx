
import { useState, useEffect } from 'react';
import { toast } from 'sonner';
import { api } from '../../lib/api';
import { Requirement } from '../../lib/types';
import { AUTH_STEP_UP_REQUIRED, dispatchStepUpComplete, dispatchStepUpCancelled, StepUpRequiredEvent } from '../../lib/events';

interface UserFactor {
    id: string;
    factor_type: 'totp' | 'passkey';
    status: string;
}

export default function StepUpModal() {
    const [isOpen, setIsOpen] = useState(false);
    const [factors, setFactors] = useState<UserFactor[]>([]);
    const [selectedFactorId, setSelectedFactorId] = useState<string>('');
    const [code, setCode] = useState('');
    const [loading, setLoading] = useState(false);
    const [verifying, setVerifying] = useState(false);
    const [requirement, setRequirement] = useState<Requirement | undefined>(undefined);

    useEffect(() => {
        const handleStepUpRequired = async (e: Event) => {
            const event = e as StepUpRequiredEvent;
            setIsOpen(true);
            setLoading(true);
            const req = event.detail.requirement;
            setRequirement(req);

            try {
                // Fetch enrolled factors (this might be a chicken-egg problem if this endpoint is also protected?)
                // Assuming /user/factors is allowed or at least AAL1 allowed.
                // If /user/factors requires AAL2, we are stuck. 
                // However, usually factor listing is allowed for the user to select one.
                const { data } = await api.get<UserFactor[]>('/api/v1/user/factors');

                let availableFactors = data;

                // Filter based on requirement
                if (req) {
                    if (req.require_phishing_resistant) {
                        availableFactors = availableFactors.filter(f => f.factor_type === 'passkey');
                    }
                    // future: filter by acceptable_capabilities if factors have capabilities data
                }

                setFactors(availableFactors);
                if (availableFactors.length > 0) {
                    setSelectedFactorId(availableFactors[0].id);
                }
            } catch (err) {
                console.error("Failed to load factors", err);
                toast.error("Failed to load authentication factors.");
                // We might want to fallback to a manual ID entry or just show error?
            } finally {
                setLoading(false);
            }
        };

        window.addEventListener(AUTH_STEP_UP_REQUIRED, handleStepUpRequired);
        return () => window.removeEventListener(AUTH_STEP_UP_REQUIRED, handleStepUpRequired);
    }, []);

    const handleVerify = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!selectedFactorId || !code) return;

        setVerifying(true);
        try {
            await api.post('/api/v1/auth/step-up', {
                factor_id: selectedFactorId,
                code
            });

            toast.success("Identity verified");
            setIsOpen(false);
            setCode('');
            dispatchStepUpComplete();
        } catch (err: any) {
            console.error("Verification failed", err);
            toast.error(err.response?.data || "Verification failed");
        } finally {
            setVerifying(false);
        }
    };

    const handleCancel = () => {
        setIsOpen(false);
        setCode('');
        dispatchStepUpCancelled();
        toast.info("Verification cancelled");
    };

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
            <div className="w-full max-w-md bg-slate-900 border border-slate-700 rounded-xl shadow-2xl p-6">
                <div className="mb-6">
                    <h2 className="text-xl font-bold text-white mb-2">Security Verification Required</h2>
                    <p className="text-sm text-slate-400">
                        {requirement?.required_assurance
                            ? `This action requires ${requirement.required_assurance} assurance.`
                            : requirement?.require_phishing_resistant
                                ? "This action requires a phishing-resistant authentication method (e.g. Passkey)."
                                : "This action requires additional authentication. Please verify your identity to continue."
                        }
                    </p>
                </div>

                {loading ? (
                    <div className="flex justify-center p-8">
                        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500"></div>
                    </div>
                ) : factors.length === 0 ? (
                    <div className="text-center py-4">
                        <p className="text-yellow-400 mb-4">No authentication factors found.</p>
                        <p className="text-sm text-slate-400 mb-4">You need to enroll in MFA to perform this action.</p>
                        <div className="flex justify-end gap-3">
                            <button
                                onClick={handleCancel}
                                className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-white transition-colors"
                            >
                                Cancel
                            </button>
                            <a
                                href="/security" // Redirect to MFA enrollment
                                className="px-4 py-2 text-sm font-medium bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg transition-colors"
                            >
                                Enroll MFA
                            </a>
                        </div>
                    </div>
                ) : (
                    <form onSubmit={handleVerify}>
                        <div className="space-y-4 mb-6">
                            <div>
                                <label className="block text-xs font-medium text-slate-400 uppercase tracking-wider mb-1.5">
                                    Select Method
                                </label>
                                <select
                                    value={selectedFactorId}
                                    onChange={(e) => setSelectedFactorId(e.target.value)}
                                    className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
                                >
                                    {factors.map(f => (
                                        <option key={f.id} value={f.id}>
                                            {f.factor_type.toUpperCase()}
                                        </option>
                                    ))}
                                </select>
                            </div>

                            {/* Assuming TOTP for now. Passkey would need a button trigger */}
                            <div>
                                <label className="block text-xs font-medium text-slate-400 uppercase tracking-wider mb-1.5">
                                    Verification Code
                                </label>
                                <input
                                    type="text"
                                    value={code}
                                    onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                    placeholder="000000"
                                    className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-white font-mono tracking-widest text-center text-lg focus:outline-none focus:ring-2 focus:ring-indigo-500"
                                    autoFocus
                                />
                            </div>
                        </div>

                        <div className="flex justify-end gap-3">
                            <button
                                type="button"
                                onClick={handleCancel}
                                className="px-4 py-2 text-sm font-medium text-slate-300 hover:text-white transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                type="submit"
                                disabled={verifying || !code}
                                className="px-4 py-2 text-sm font-medium bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg transition-colors flex items-center gap-2"
                            >
                                {verifying && <div className="animate-spin h-4 w-4 border-2 border-white/20 border-t-white rounded-full"></div>}
                                Verify
                            </button>
                        </div>
                    </form>
                )}
            </div>
        </div>
    );
}
