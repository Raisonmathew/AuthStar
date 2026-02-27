import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { api } from './lib/api/client';

const RETRY_BACKOFF_MS = [1000, 2000, 5000, 10000];

async function tryPrefetchWithBackoff(): Promise<void> {
    let lastError: unknown;
    for (const delay of RETRY_BACKOFF_MS) {
        try {
            await api.prefetchRuntimeKeys();
            return;
        } catch (err) {
            lastError = err;
            await new Promise((resolve) => setTimeout(resolve, delay));
        }
    }
    throw lastError;
}

async function bootstrap() {
    // Start token refresh
    api.startTokenRefresh();

    try {
        await tryPrefetchWithBackoff();
    } catch (err) {
        const rootEl = document.getElementById('root')!;
        const root = ReactDOM.createRoot(rootEl);

        const RetryScreen = () => {
            const [busy, setBusy] = React.useState(false);
            const [error, setError] = React.useState<string | null>(null);

            const retry = async () => {
                setBusy(true);
                setError(null);
                try {
                    await tryPrefetchWithBackoff();
                    root.render(
                        <React.StrictMode>
                            <App />
                        </React.StrictMode>
                    );
                } catch (e) {
                    setError(e instanceof Error ? e.message : 'Retry failed');
                } finally {
                    setBusy(false);
                }
            };

            return (
                <div style={{ padding: '24px', fontFamily: 'system-ui, sans-serif' }}>
                    <h1 style={{ fontSize: '20px', marginBottom: '8px' }}>Runtime key fetch failed</h1>
                    <p style={{ margin: '0 0 12px 0' }}>
                        Unable to verify attestations. Check backend availability or key access policy.
                    </p>
                    {error ? <p style={{ color: '#b91c1c', margin: '0 0 12px 0' }}>{error}</p> : null}
                    <button
                        type="button"
                        onClick={retry}
                        disabled={busy}
                        style={{
                            padding: '8px 12px',
                            borderRadius: '6px',
                            border: '1px solid #111827',
                            background: busy ? '#e5e7eb' : '#111827',
                            color: busy ? '#111827' : '#ffffff',
                            cursor: busy ? 'not-allowed' : 'pointer',
                        }}
                    >
                        {busy ? 'Retrying...' : 'Retry'}
                    </button>
                </div>
            );
        };

        root.render(
            <React.StrictMode>
                <RetryScreen />
            </React.StrictMode>
        );
        console.error('Runtime keys prefetch failed:', err);
        return;
    }

    ReactDOM.createRoot(document.getElementById('root')!).render(
        <React.StrictMode>
            <App />
        </React.StrictMode>
    );
}

void bootstrap();
