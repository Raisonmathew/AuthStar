import { IDaaSClient } from '@idaas/core';
import type { User } from '@idaas/core';
import { SHARED_STYLES } from './styles';

const TEMPLATE = `
<style>
${SHARED_STYLES}
.idaas-user-btn {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 6px 12px;
    border: 1px solid #e5e7eb;
    border-radius: 9999px;
    background: #fff;
    cursor: pointer;
    font-size: 14px;
    position: relative;
}
.idaas-avatar {
    width: 32px;
    height: 32px;
    border-radius: 50%;
    background: var(--idaas-primary, #3B82F6);
    color: #fff;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 600;
    font-size: 13px;
}
.idaas-dropdown {
    position: absolute;
    top: calc(100% + 8px);
    right: 0;
    min-width: 200px;
    background: #fff;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    box-shadow: 0 4px 16px rgba(0,0,0,.12);
    z-index: 9999;
    overflow: hidden;
}
.idaas-dropdown__item {
    display: block;
    width: 100%;
    padding: 10px 16px;
    border: none;
    background: none;
    text-align: left;
    font-size: 14px;
    cursor: pointer;
    color: #374151;
}
.idaas-dropdown__item:hover { background: #f9fafb; }
.idaas-dropdown__item--danger { color: #dc2626; }
.idaas-dropdown__divider { height: 1px; background: #f3f4f6; margin: 4px 0; }
</style>
<div style="position:relative;display:inline-block">
  <button class="idaas-user-btn" id="toggle-btn" aria-haspopup="true" aria-expanded="false">
    <span class="idaas-avatar" id="avatar"></span>
    <span id="display-name">…</span>
  </button>
  <div class="idaas-dropdown" id="dropdown" hidden></div>
</div>
`;

/**
 * `<idaas-user-button>` Web Component
 *
 * Displays the current user's avatar and name. On click shows a dropdown
 * with a Sign out option (and any custom items injected via the `menu-items` attribute).
 *
 * Usage:
 * ```html
 * <idaas-user-button api-url="https://api.example.com"></idaas-user-button>
 * ```
 *
 * Events fired (bubble to document):
 *  - `idaas:signed-out` — user signed out successfully
 */
export class IDaaSUserButton extends HTMLElement {
    static observedAttributes = ['api-url'];

    private shadow: ShadowRoot;
    private client: IDaaSClient | null = null;
    private user: User | null = null;

    constructor() {
        super();
        this.shadow = this.attachShadow({ mode: 'open' });
    }

    connectedCallback() {
        this.shadow.innerHTML = TEMPLATE;

        const toggleBtn = this.shadow.getElementById('toggle-btn') as HTMLButtonElement;
        toggleBtn.addEventListener('click', () => this.toggleDropdown());

        // Close dropdown on outside click
        document.addEventListener('click', (e) => {
            if (!this.contains(e.target as Node)) {
                this.closeDropdown();
            }
        });

        this.loadUser();
    }

    attributeChangedCallback() {
        if (this.isConnected) this.loadUser();
    }

    private get apiUrl(): string {
        return this.getAttribute('api-url') ?? '';
    }

    private async loadUser() {
        if (!this.apiUrl) return;
        this.client = new IDaaSClient({ apiUrl: this.apiUrl });
        try {
            this.user = await this.client.getCurrentUser();
            this.renderUser(this.user);
        } catch {
            // User not authenticated — component quietly hides itself
            this.style.display = 'none';
        }
    }

    private renderUser(user: User) {
        const avatar = this.shadow.getElementById('avatar') as HTMLSpanElement;
        const displayName = this.shadow.getElementById('display-name') as HTMLSpanElement;

        const initials = [user.firstName, user.lastName]
            .filter(Boolean)
            .map(n => n![0].toUpperCase())
            .join('') || user.email[0].toUpperCase();

        avatar.textContent = initials;
        displayName.textContent = user.firstName
            ? `${user.firstName} ${user.lastName ?? ''}`.trim()
            : user.email;

        this.buildDropdown(user);
        this.style.display = '';
    }

    private buildDropdown(user: User) {
        const dropdown = this.shadow.getElementById('dropdown') as HTMLDivElement;
        dropdown.innerHTML = '';

        // User info header
        const header = document.createElement('div');
        header.style.cssText = 'padding:12px 16px;border-bottom:1px solid #f3f4f6;font-size:13px;color:#6b7280';
        header.textContent = user.email;
        dropdown.appendChild(header);

        // Sign out
        const signOutBtn = document.createElement('button');
        signOutBtn.className = 'idaas-dropdown__item idaas-dropdown__item--danger';
        signOutBtn.textContent = 'Sign out';
        signOutBtn.addEventListener('click', () => this.handleSignOut());
        dropdown.appendChild(signOutBtn);
    }

    private async handleSignOut() {
        if (!this.client) return;
        try {
            await this.client.signOut();
        } catch {
            // Best-effort sign out
        }
        this.closeDropdown();
        this.dispatchEvent(new CustomEvent('idaas:signed-out', { bubbles: true, composed: true }));
    }

    private toggleDropdown() {
        const dropdown = this.shadow.getElementById('dropdown') as HTMLDivElement;
        const toggleBtn = this.shadow.getElementById('toggle-btn') as HTMLButtonElement;
        const isOpen = !dropdown.hidden;
        dropdown.hidden = isOpen;
        toggleBtn.setAttribute('aria-expanded', String(!isOpen));
    }

    private closeDropdown() {
        const dropdown = this.shadow.getElementById('dropdown') as HTMLDivElement;
        const toggleBtn = this.shadow.getElementById('toggle-btn') as HTMLButtonElement;
        dropdown.hidden = true;
        toggleBtn.setAttribute('aria-expanded', 'false');
    }
}

customElements.define('idaas-user-button', IDaaSUserButton);
