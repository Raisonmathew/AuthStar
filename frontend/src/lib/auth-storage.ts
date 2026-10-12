/**
 * In-memory token storage to avoid circular dependencies between AuthContext and API client.
 *
 * In development, Vite HMR full-reloads wipe module-level variables. We use
 * import.meta.hot.data to survive HMR updates so the user doesn't get kicked
 * back to the dashboard on every file save. This is dev-only — production
 * builds tree-shake all import.meta.hot branches.
 */
let _inMemoryToken: string | null =
  typeof import.meta !== 'undefined' && import.meta.hot?.data?.inMemoryToken
    ? (import.meta.hot.data.inMemoryToken as string)
    : null;

export function getInMemoryToken(): string | null {
  return _inMemoryToken;
}

export function setInMemoryToken(token: string | null): void {
  _inMemoryToken = token;
  if (typeof import.meta !== 'undefined' && import.meta.hot) {
    const hotData = import.meta.hot.data as Record<string, unknown> | undefined;
    if (hotData) {
      hotData.inMemoryToken = token;
    }
  }
}

// Accept HMR updates for this module without a full page reload
if (import.meta.hot) {
  import.meta.hot.accept();
}
