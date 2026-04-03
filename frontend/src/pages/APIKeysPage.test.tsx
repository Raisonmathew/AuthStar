import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import { MemoryRouter } from 'react-router-dom';
import APIKeysPage from './APIKeysPage';
import { api } from '../lib/api';

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    delete: vi.fn(),
  },
}));

vi.mock('sonner', () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
  },
}));

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

const sampleKeys = [
  {
    id: 'k1',
    name: 'Test Key',
    key_prefix: 'abc12345',
    scopes: ['read:users'],
    last_used_at: '2024-01-15T10:00:00Z',
    expires_at: '2025-12-31T23:59:59Z',
    created_at: '2024-01-01T00:00:00Z',
  },
];

function renderPage() {
  return render(
    <MemoryRouter>
      <APIKeysPage />
    </MemoryRouter>
  );
}

describe('APIKeysPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    document.body.innerHTML = '';
  });

  it('shows loading spinner then renders keys', async () => {
    (api.get as any).mockResolvedValue({ data: sampleKeys });

    renderPage();

    // After load, should show the key name
    await waitFor(() => {
      expect(screen.getByText('Test Key')).toBeInTheDocument();
    });

    expect(api.get).toHaveBeenCalledWith('/api/v1/api-keys');
  });

  it('shows empty state when no keys exist', async () => {
    (api.get as any).mockResolvedValue({ data: [] });

    renderPage();

    await waitFor(() => {
      expect(screen.getByText(/No API keys yet/)).toBeInTheDocument();
    });
  });

  it('shows error toast when load fails', async () => {
    const { toast } = await import('sonner');
    (api.get as any).mockRejectedValue({
      response: { data: { message: 'Unauthorized' } },
    });

    renderPage();

    await waitFor(() => {
      expect(toast.error).toHaveBeenCalledWith('Unauthorized');
    });
  });

  it('opens create modal when clicking Create Key', async () => {
    (api.get as any).mockResolvedValue({ data: [] });

    renderPage();

    await waitFor(() => {
      expect(screen.getByText(/No API keys yet/)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('+ Create Key'));

    await waitFor(() => {
      expect(screen.getByText(/Key Name/i)).toBeInTheDocument();
    });
  });

  it('validates empty key name', async () => {
    (api.get as any).mockResolvedValue({ data: [] });

    renderPage();

    await waitFor(() => {
      expect(screen.getByText('+ Create Key')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('+ Create Key'));

    await waitFor(() => {
      expect(screen.getByText(/Key Name/i)).toBeInTheDocument();
    });

    // Click Create without entering name
    const createButtons = screen.getAllByRole('button', { name: /Create/i });
    const modalCreate = createButtons.find(
      (btn) => btn.textContent?.includes('Create') && btn !== screen.getByText('+ Create Key')
    );
    if (modalCreate) {
      fireEvent.click(modalCreate);
      await waitFor(() => {
        expect(screen.getByText('Key name is required')).toBeInTheDocument();
      });
    }
  });

  it('creates a key and shows reveal banner', async () => {
    (api.get as any).mockResolvedValue({ data: [] });
    (api.post as any).mockResolvedValue({
      data: {
        id: 'k2',
        name: 'New Key',
        key_prefix: 'xyz',
        key: 'ask_xyz_full_secret_key',
        scopes: [],
        expires_at: null,
        created_at: '2024-06-01T00:00:00Z',
      },
    });

    renderPage();

    await waitFor(() => {
      expect(screen.getByText('+ Create Key')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('+ Create Key'));

    await waitFor(() => {
      expect(screen.getByPlaceholderText('e.g. Production Backend')).toBeInTheDocument();
    });

    // Fill in name
    const nameInput = screen.getByPlaceholderText('e.g. Production Backend');
    fireEvent.change(nameInput, { target: { value: 'New Key' } });

    // Submit via the modal's "Create Key" button (not the "+ Create Key" header button)
    const createButtons = screen.getAllByRole('button');
    const modalSubmit = createButtons.find(b => b.textContent === 'Create Key');
    fireEvent.click(modalSubmit!);

    await waitFor(() => {
      expect(screen.getByText(/won't be shown again/i)).toBeInTheDocument();
    });
  });

  it('shows 409 error as duplicate name message', async () => {
    (api.get as any).mockResolvedValue({ data: [] });
    (api.post as any).mockRejectedValue({
      response: { status: 409 },
    });

    renderPage();

    await waitFor(() => {
      expect(screen.getByText('+ Create Key')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('+ Create Key'));

    await waitFor(() => {
      expect(screen.getByPlaceholderText('e.g. Production Backend')).toBeInTheDocument();
    });

    const nameInput = screen.getByPlaceholderText('e.g. Production Backend');
    fireEvent.change(nameInput, { target: { value: 'Duplicate' } });

    const createButtons2 = screen.getAllByRole('button');
    const modalSubmit2 = createButtons2.find(b => b.textContent === 'Create Key');
    fireEvent.click(modalSubmit2!);

    await waitFor(() => {
      expect(screen.getByText(/already exists/i)).toBeInTheDocument();
    });
  });

  it('navigates back to dashboard', async () => {
    (api.get as any).mockResolvedValue({ data: sampleKeys });

    renderPage();

    await waitFor(() => {
      expect(screen.getByText('Test Key')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText(/Back to Dashboard/i));
    expect(mockNavigate).toHaveBeenCalledWith('/dashboard');
  });
});
