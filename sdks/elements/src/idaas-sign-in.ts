import { FlowManager } from '@idaas/core';
import { renderField } from './field-renderer';
import { renderOAuthButton } from './oauth-button';
import { SHARED_STYLES } from './styles';

const TEMPLATE = `
<style>${SHARED_STYLES}</style>
<form class="idaas-form" novalidate>
  <div class="idaas-fields" id="fields-container"></div>
  <div class="idaas-oauth" id="oauth-container"></div>
  <p class="idaas-error" id="error-msg" hidden></p>
  <button type="submit" class="idaas-btn idaas-btn--primary" id="submit-btn">Sign in</button>
</form>
`;

/**
 * `<idaas-sign-in>` Web Component
 *
 * Usage:
 * ```html
 * <idaas-sign-in api-url="https://api.example.com" org-id="my-org"></idaas-sign-in>
 * ```
 *
 * Events fired (bubble to document):
 *  - `idaas:success` — authentication complete, `detail: { decisionRef }`
 *  - `idaas:error`   — unrecoverable error, `detail: { message }`
 */
export class IDaaSSignIn extends HTMLElement {
    static observedAttributes = ['api-url', 'org-id'];

    private shadow: ShadowRoot;
    private fm: FlowManager | null = null;
    private fieldsContainer!: HTMLDivElement;
    private oauthContainer!: HTMLDivElement;
    private errorMsg!: HTMLParagraphElement;
    private submitBtn!: HTMLButtonElement;
    private form!: HTMLFormElement;

    constructor() {
        super();
        this.shadow = this.attachShadow({ mode: 'open' });
    }

    connectedCallback() {
        this.shadow.innerHTML = TEMPLATE;
        this.fieldsContainer = this.shadow.getElementById('fields-container') as HTMLDivElement;
        this.oauthContainer = this.shadow.getElementById('oauth-container') as HTMLDivElement;
        this.errorMsg = this.shadow.getElementById('error-msg') as HTMLParagraphElement;
        this.submitBtn = this.shadow.getElementById('submit-btn') as HTMLButtonElement;
        this.form = this.shadow.querySelector('form') as HTMLFormElement;

        this.form.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleSubmit();
        });

        this.startFlow();
    }

    attributeChangedCallback() {
        if (this.isConnected) this.startFlow();
    }

    private get apiUrl(): string {
        return this.getAttribute('api-url') ?? '';
    }

    private get orgId(): string {
        return this.getAttribute('org-id') ?? '';
    }

    private async startFlow() {
        if (!this.apiUrl || !this.orgId) return;

        this.fm = new FlowManager({ apiUrl: this.apiUrl, orgId: this.orgId });

        this.fm.addEventListener('step', (e: Event) => {
            const { step, manifest } = (e as CustomEvent).detail;
            this.renderStep(step, manifest);
        });

        this.fm.addEventListener('decision', (e: Event) => {
            const detail = (e as CustomEvent).detail;
            this.dispatchEvent(new CustomEvent('idaas:success', {
                bubbles: true,
                composed: true,
                detail,
            }));
        });

        this.fm.addEventListener('error', (e: Event) => {
            const { message } = (e as CustomEvent).detail;
            this.showError(message);
        });

        try {
            await this.fm.init();
        } catch {
            // Error already dispatched via FlowManager 'error' event
        }
    }

    private renderStep(step: Record<string, unknown>, manifest: unknown) {
        this.fieldsContainer.innerHTML = '';
        this.oauthContainer.innerHTML = '';
        this.hideError();

        if (step.type === 'credentials') {
            const fields = (step.fields as Array<Record<string, unknown>>) ?? [];
            for (const field of fields) {
                renderField(field as never, this.fieldsContainer);
            }
        } else if (step.type === 'email') {
            renderField(
                { name: 'email', field_type: 'Email', label: String(step.label ?? 'Email'), required: true, order: 0 },
                this.fieldsContainer,
            );
        } else if (step.type === 'password') {
            renderField(
                { name: 'password', field_type: 'Password', label: String(step.label ?? 'Password'), required: true, order: 0 },
                this.fieldsContainer,
            );
        }

        // Render OAuth buttons from manifest if on the first step
        if (manifest && (manifest as Record<string, unknown>).flows) {
            const providers = ((manifest as Record<string, unknown>).flows as Record<string, unknown>);
            const signIn = (providers.sign_in as Record<string, unknown>);
            const oauthProviders = (signIn?.oauth_providers as Array<Record<string, unknown>>) ?? [];
            for (const p of oauthProviders) {
                renderOAuthButton(p as never, this.apiUrl, this.oauthContainer);
            }
        }
    }

    private async handleSubmit() {
        if (!this.fm) return;
        this.setLoading(true);
        this.hideError();

        const inputMap = this.collectInputs();
        const identifier = inputMap.get('email') ?? inputMap.get('identifier') ?? '';

        try {
            if (identifier) {
                await this.fm.identify(identifier);
            }
            const password = inputMap.get('password');
            if (password) {
                await this.fm.submit('Password', password);
            }
        } catch {
            // Error handled via 'error' event
        } finally {
            this.setLoading(false);
        }
    }

    private collectInputs(): Map<string, string> {
        const map = new Map<string, string>();
        this.fieldsContainer.querySelectorAll<HTMLInputElement>('input').forEach(input => {
            map.set(input.name, input.value);
        });
        return map;
    }

    private showError(message: string) {
        this.errorMsg.textContent = message;
        this.errorMsg.hidden = false;
    }

    private hideError() {
        this.errorMsg.hidden = true;
    }

    private setLoading(loading: boolean) {
        this.submitBtn.disabled = loading;
        this.submitBtn.textContent = loading ? 'Signing in…' : 'Sign in';
    }
}

customElements.define('idaas-sign-in', IDaaSSignIn);
