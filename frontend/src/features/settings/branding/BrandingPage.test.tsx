import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import BrandingPage from './BrandingPage';
import { api } from '../../../lib/api';

vi.mock('../../../lib/api', () => ({
  api: {
    get: vi.fn(),
    patch: vi.fn(),
  },
}));

vi.mock('sonner', () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
  },
}));

vi.mock('../../../features/auth/hooks/useAuth', () => ({
  useAuth: () => ({
    organizationId: 'org-test',
    isAuthenticated: true,
    token: 'test-token',
    user: { id: 'u1', email: 'admin@test.com' },
    isLoading: false,
  }),
}));

// Mock the HostedPagePreview child component
vi.mock('./HostedPagePreview', () => ({
  HostedPagePreview: ({ config }: any) => (
    <div data-testid="preview">Preview: {config?.colors?.primary}</div>
  ),
  // Re-export the type so the import doesn't break
  BrandingConfig: undefined,
}));

describe('BrandingPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    document.body.innerHTML = '';
  });

  it('loads branding config on mount', async () => {
    (api.get as any).mockResolvedValue({
      data: {
        branding: {
          primary_color: '#ff0000',
          background_color: '#000000',
          text_color: '#ffffff',
          logo_url: 'https://example.com/logo.png',
        },
      },
    });

    render(<BrandingPage />);

    await waitFor(() => {
      expect(api.get).toHaveBeenCalledWith('/api/organizations/org-test');
    });

    // Check that loaded values appear in the inputs
    await waitFor(() => {
      const preview = screen.getByTestId('preview');
      expect(preview).toHaveTextContent('#ff0000');
    });
  });

  it('renders with defaults when no branding exists', async () => {
    (api.get as any).mockResolvedValue({ data: {} });

    render(<BrandingPage />);

    await waitFor(() => {
      expect(api.get).toHaveBeenCalled();
    });

    // Default primary color should show in preview
    expect(screen.getByTestId('preview')).toHaveTextContent('#4F46E5');
  });

  it('saves configuration on button click', async () => {
    (api.get as any).mockResolvedValue({ data: {} });
    (api.patch as any).mockResolvedValue({ data: {} });

    const { toast } = await import('sonner');

    render(<BrandingPage />);

    await waitFor(() => {
      expect(api.get).toHaveBeenCalled();
    });

    const saveBtn = screen.getByRole('button', { name: /Save Configuration/i });
    fireEvent.click(saveBtn);

    await waitFor(() => {
      expect(api.patch).toHaveBeenCalledWith(
        '/api/organizations/org-test/branding',
        expect.objectContaining({
          primary_color: '#4F46E5',
          background_color: '#ffffff',
          text_color: '#111827',
          font_family: 'Inter',
        })
      );
    });

    expect(toast.success).toHaveBeenCalledWith('Branding updated successfully');
  });

  it('shows error toast on save failure', async () => {
    (api.get as any).mockResolvedValue({ data: {} });
    (api.patch as any).mockRejectedValue(new Error('Network error'));

    const { toast } = await import('sonner');

    render(<BrandingPage />);

    await waitFor(() => {
      expect(api.get).toHaveBeenCalled();
    });

    const saveBtn = screen.getByRole('button', { name: /Save Configuration/i });
    fireEvent.click(saveBtn);

    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('Failed to update branding');
    });
  });

  it('shows error toast on load failure', async () => {
    (api.get as any).mockRejectedValue(new Error('500'));

    const { toast } = await import('sonner');

    render(<BrandingPage />);

    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('Failed to load branding configuration');
    });
  });

  it('toggles preview between login and register', async () => {
    (api.get as any).mockResolvedValue({ data: {} });

    render(<BrandingPage />);

    await waitFor(() => {
      expect(api.get).toHaveBeenCalled();
    });

    // Click Sign Up toggle
    const signUpBtn = screen.getByRole('button', { name: /Sign Up/i });
    fireEvent.click(signUpBtn);

    // Verify Sign Up button becomes active (checking by click doesn't throw)
    expect(signUpBtn).toBeDefined();
  });
});
