/**
 * In-memory token storage to avoid circular dependencies between AuthContext and API client.
 */
let _inMemoryToken: string | null = null;

export function getInMemoryToken(): string | null {
  return _inMemoryToken;
}

export function setInMemoryToken(token: string | null): void {
  _inMemoryToken = token;
}
