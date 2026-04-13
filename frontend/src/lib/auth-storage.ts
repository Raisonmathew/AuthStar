/**
 * In-memory token storage to avoid circular dependencies between AuthContext and API client.
 *
 * In development, Vite HMR full-reloads wipe module-level variables. We use
 * import.meta.hot.data to survive HMR updates so the user doesn't get kicked
 * back to the dashboard on every file save. This is dev-only — production
 * builds tree-shake all import.meta.hot branches.
 */
let _inMemoryToken: string | null =
  (import.meta.hot?.data?.inMemoryToken as string | null) ?? null;

export function getInMemoryToken(): string | null {
  return _inMemoryToken;
}

export function setInMemoryToken(token: string | null): void {
  _inMemoryToken = token;
  if (import.meta.hot) {
    import.meta.hot.data.inMemoryToken = token;
  }
}

// Accept HMR updates for this module without a full page reload
if (import.meta.hot) {
  import.meta.hot.accept();
}
