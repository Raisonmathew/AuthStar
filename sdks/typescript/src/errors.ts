/**
 * All AuthStar SDK errors are instances of `AuthstarError`.
 * Sub-types narrow on `status` for common cases:
 *
 * | status | meaning        |
 * |--------|----------------|
 * | 0      | Network error  |
 * | 401    | Unauthorized   |
 * | 403    | Forbidden      |
 * | 404    | Not found      |
 * | 429    | Rate limited   |
 * | 5xx    | Server error   |
 */
export class AuthstarError extends Error {
  /** HTTP status code. `0` for network-level failures (no response received). */
  readonly status: number;
  /** Machine-readable error code from the API response body. */
  readonly code: string;

  constructor(message: string, status: number, code: string) {
    super(message);
    this.name = "AuthstarError";
    this.status = status;
    this.code = code;
    // Restore prototype chain for `instanceof` checks in transpiled code.
    Object.setPrototypeOf(this, new.target.prototype);
  }

  get isNetworkError() { return this.status === 0; }
  get isAuthError()    { return this.status === 401 || this.status === 403; }
  get isNotFound()     { return this.status === 404; }
  get isRateLimited()  { return this.status === 429; }
  get isServerError()  { return this.status >= 500; }
}
