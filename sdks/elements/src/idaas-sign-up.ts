import { FlowManager } from '@idaas/core';
import type { FieldDescriptor, SdkManifest } from '@idaas/core';
import { renderField } from './field-renderer';
import { SHARED_STYLES } from './styles';

const TEMPLATE = `
<style>${SHARED_STYLES}</style>
<form class="idaas-form" novalidate>
  <div class="idaas-fields" id="fields-container"></div>
  <p class="idaas-error" id="error-msg" hidden></p>
  <button type="submit" class="idaas-btn idaas-btn--primary" id="submit-btn">Create account</button>
</form>
`;

const DEFAULT_SIGN_UP_FIELDS: FieldDescriptor[] = [
    { name: 'email', field_type: 'Email', label: 'Email address', required: true, order: 0 },
    { name: 'password', field_type: 'Password', label: 'Password', required: true, order: 1 },
];

/**
 * `<idaas-sign-up>` Web Component
 *
 * Renders a sign-up form driven entirely by the tenant manifest.
 * Fields are dynamically assembled from `manifest.flows.sign_up.fields`,
 * falling back to email + password when no manifest is available.
 *
 * Usage:
 * ```html
 * <idaas-sign-up api-url="https://api.example.com" org-id="my-org"></idaas-sign-up>
 * ```
 *
 * Events fired (bubble to document):
 *  - `idaas:success` — sign-up decision ready, `detail: { decisionRef }`
 *  - `idaas:error`   — unrecoverable error, `detail: { message }`
 */
export class IDaaSSignUp extends HTMLElement {
    static observedAttributes = ['api-url', 'org-id'];

    private shadow: ShadowRoot;
    private fm: FlowManager | null = null;
    private fieldsContainer!: HTMLDivElement;
    private errorMsg!: HTMLParagraphElement;
    private submitBtn!: HTMLButtonElement;
    private form!: HTMLFormElement;
    private manifestFields: FieldDescriptor[] = DEFAULT_SIGN_UP_FIELDS;

    constructor() {
        super();
        this.shadow = this.attachShadow({ mode: 'open' });
    }

    connectedCallback() {
        this.shadow.innerHTML = TEMPLATE;
        this.fieldsContainer = this.shadow.getElementById('fields-container') as HTMLDivElement;
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
            const { manifest } = (e as CustomEvent).detail;
            if (manifest) this.applyManifest(manifest as SdkManifest);
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
            // Render default fields while waiting for manifest
            this.renderFields(this.manifestFields);
        } catch {
            // Error already dispatched via FlowManager 'error' event
        }
    }

    private applyManifest(manifest: SdkManifest) {
        if (manifest.flows.sign_up.fields.length > 0) {
            this.manifestFields = [...manifest.flows.sign_up.fields].sort((a, b) => a.order - b.order);
            this.renderFields(this.manifestFields);
        }

        // Apply CSS custom properties from branding
        const b = manifest.branding;
        const host = this.shadow.host as HTMLElement;
        host.style.setProperty('--idaas-primary', b.primary_color);
        host.style.setProperty('--idaas-bg', b.background_color);
        host.style.setProperty('--idaas-text', b.text_color);
        host.style.setProperty('--idaas-font', b.font_family);
    }

    private renderFields(fields: FieldDescriptor[]) {
        this.fieldsContainer.innerHTML = '';
        for (const field of fields) {
            renderField(field, this.fieldsContainer);
        }
    }

    private async handleSubmit() {
        if (!this.fm) return;
        this.setLoading(true);
        this.hideError();

        const values = this.collectInputs();
        const email = values.get('email') ?? '';

        try {
            await this.fm.identify(email);
            // Submit remaining fields (password etc.) as credentials
            const password = values.get('password');
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
        this.submitBtn.textContent = loading ? 'Creating account…' : 'Create account';
    }
}

customElements.define('idaas-sign-up', IDaaSSignUp);
