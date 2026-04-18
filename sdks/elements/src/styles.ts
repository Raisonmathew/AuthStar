/** Shared base CSS injected into every Shadow DOM root. */
export const SHARED_STYLES = `
:host {
    font-family: var(--idaas-font, Inter, system-ui, sans-serif);
    color: var(--idaas-text, #1F2937);
    box-sizing: border-box;
    display: block;
}
*, *::before, *::after { box-sizing: inherit; }

.idaas-logo {
    display: flex;
    justify-content: center;
    margin-bottom: 8px;
}
.idaas-logo__img {
    max-height: 48px;
    max-width: 200px;
    object-fit: contain;
}

.idaas-form {
    display: flex;
    flex-direction: column;
    gap: 14px;
}

.idaas-field {
    display: flex;
    flex-direction: column;
    gap: 4px;
}
.idaas-field__label {
    font-size: 13px;
    font-weight: 500;
    color: var(--idaas-text, #374151);
}
.idaas-field__input {
    width: 100%;
    padding: 10px 12px;
    border: 1px solid #d1d5db;
    border-radius: 6px;
    font-size: 15px;
    outline: none;
    transition: border-color .15s;
    background: var(--idaas-bg, #fff);
    color: var(--idaas-text, #1F2937);
}
.idaas-field__input:focus {
    border-color: var(--idaas-primary, #3B82F6);
    box-shadow: 0 0 0 3px color-mix(in srgb, var(--idaas-primary, #3B82F6) 20%, transparent);
}

.idaas-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 11px 20px;
    border: none;
    border-radius: 6px;
    font-size: 15px;
    font-weight: 600;
    cursor: pointer;
    transition: opacity .15s, filter .15s;
    width: 100%;
}
.idaas-btn:disabled { opacity: .6; cursor: not-allowed; }
.idaas-btn--primary {
    background: var(--idaas-primary, #3B82F6);
    color: #fff;
}
.idaas-btn--primary:hover:not(:disabled) { filter: brightness(1.08); }

.idaas-oauth {
    display: flex;
    flex-direction: column;
    gap: 8px;
}
.idaas-oauth-btn {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    justify-content: center;
    padding: 10px 16px;
    border: 1px solid #d1d5db;
    border-radius: 6px;
    background: #fff;
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    width: 100%;
    transition: background .15s;
}
.idaas-oauth-btn:hover { background: #f9fafb; }

.idaas-error {
    font-size: 13px;
    color: #dc2626;
    margin: 0;
    padding: 8px 12px;
    background: #fef2f2;
    border-radius: 6px;
    border: 1px solid #fecaca;
}
`;
