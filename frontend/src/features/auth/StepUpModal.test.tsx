import { render, screen, waitFor } from '@testing-library/react';
import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import StepUpModal from './StepUpModal';
import { AUTH_STEP_UP_REQUIRED } from '../../lib/events';
import { api } from '../../lib/api';

// Mock the API
vi.mock('../../lib/api', () => ({
    api: {
        get: vi.fn(),
        post: vi.fn()
    }
}));

// Mock toast
vi.mock('sonner', () => ({
    toast: {
        success: vi.fn(),
        error: vi.fn(),
        info: vi.fn()
    }
}));

describe('StepUpModal', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    afterEach(() => {
        // Clean up document body
        document.body.innerHTML = '';
    });

    const triggerEvent = (detail: any = {}) => {
        const event = new CustomEvent(AUTH_STEP_UP_REQUIRED, { detail });
        window.dispatchEvent(event);
    };

    it('renders nothing initially', () => {
        render(<StepUpModal />);
        expect(screen.queryByText(/Security Verification Required/i)).not.toBeInTheDocument();
    });

    it('opens and displays default message when event is triggered', async () => {
        render(<StepUpModal />);

        // Mock factors response
        (api.get as any).mockResolvedValue({
            data: [{ id: '1', factor_type: 'totp', status: 'active' }]
        });

        triggerEvent({ originalRequestConfig: {} });

        await waitFor(() => {
            expect(screen.getByText(/Security Verification Required/i)).toBeInTheDocument();
        });
        expect(screen.getByText(/This action requires additional authentication/i)).toBeInTheDocument();
    });

    it('displays assurance level message', async () => {
        render(<StepUpModal />);

        // Mock factors response
        (api.get as any).mockResolvedValue({
            data: [{ id: '1', factor_type: 'totp', status: 'active' }]
        });

        triggerEvent({
            originalRequestConfig: {},
            requirement: { required_assurance: 'Substantial' }
        });

        await waitFor(() => {
            expect(screen.getByText(/This action requires Substantial assurance/i)).toBeInTheDocument();
        });
    });

    it('displays phishing-resistant message and filters factors', async () => {
        render(<StepUpModal />);

        // Mock factors response with mixed types
        (api.get as any).mockResolvedValue({
            data: [
                { id: '1', factor_type: 'totp', status: 'active' },
                { id: '2', factor_type: 'passkey', status: 'active' }
            ]
        });

        triggerEvent({
            originalRequestConfig: {},
            requirement: { require_phishing_resistant: true }
        });

        await waitFor(() => {
            expect(screen.getByText(/This action requires a phishing-resistant authentication method/i)).toBeInTheDocument();
        });

        // Should not show the dropdown since only 1 factor is available after filtering
        expect(screen.queryByRole('combobox')).not.toBeInTheDocument();

        // Should show the Passkey UI directly
        expect(screen.getByText(/Use your passkey to verify/i)).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /Use Passkey/i })).toBeInTheDocument();
    });

    it('handles API errors when fetching factors', async () => {
        render(<StepUpModal />);

        (api.get as any).mockRejectedValue(new Error('Failed to fetch'));

        triggerEvent({ originalRequestConfig: {} });

        await waitFor(() => {
            expect(screen.getByText(/No authentication factors found/i)).toBeInTheDocument();
        });
    });
});
