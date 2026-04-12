import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import AppModal from './AppModal';
import { api } from '../../lib/api';

vi.mock('../../lib/api', () => ({
  api: {
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
}));

vi.mock('sonner', () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
  },
}));

describe('AppModal', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('includes the selected application type in create requests', async () => {
    (api.post as any).mockResolvedValue({
      data: {
        app: { id: 'app_123', client_id: 'client_123' },
        client_secret: 'secret_123',
      },
    });

    const onClose = vi.fn();
    const onSuccess = vi.fn();

    render(<AppModal onClose={onClose} onSuccess={onSuccess} />);

    fireEvent.change(screen.getByLabelText(/App Name/i), {
      target: { value: 'Portal App' },
    });
    fireEvent.change(screen.getByLabelText(/Application Type/i), {
      target: { value: 'mobile' },
    });
    fireEvent.change(screen.getByLabelText(/Redirect URIs/i), {
      target: { value: 'https://example.com/callback, https://example.com/alt' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Create' }));

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith('/api/admin/v1/apps', {
        name: 'Portal App',
        type: 'mobile',
        redirect_uris: ['https://example.com/callback', 'https://example.com/alt'],
        allowed_flows: ['authorization_code', 'refresh_token'],
        public_config: {
          enforce_pkce: false,
          allowed_origins: [],
        },
      });
    });

    expect(onSuccess).toHaveBeenCalledTimes(1);
  });

  it('shows application type as read-only when editing an existing app', () => {
    render(
      <AppModal
        app={{
          id: 'app_123',
          name: 'Existing App',
          type: 'web',
          redirect_uris: ['https://example.com/callback'],
        }}
        onClose={vi.fn()}
        onSuccess={vi.fn()}
      />
    );

    const appTypeSelect = screen.getByLabelText(/Application Type/i) as HTMLSelectElement;
    expect(appTypeSelect).toBeDisabled();
    expect(appTypeSelect.value).toBe('web');
    expect(screen.getByText(/immutable after creation/i)).toBeInTheDocument();
  });
});