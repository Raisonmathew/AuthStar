import type { FieldDescriptor } from '@idaas/core';

/**
 * Render a single form field into `container` based on its `FieldDescriptor`.
 * Returns the created `<input>` element so the caller can read `.value` later.
 */
export function renderField(field: FieldDescriptor, container: HTMLElement): HTMLInputElement {
    const wrapper = document.createElement('div');
    wrapper.className = 'idaas-field';

    const label = document.createElement('label');
    label.htmlFor = `idaas-field-${field.name}`;
    label.textContent = field.label + (field.required ? ' *' : '');
    label.className = 'idaas-field__label';

    const input = document.createElement('input');
    input.id = `idaas-field-${field.name}`;
    input.name = field.name;
    input.required = field.required;
    input.placeholder = field.label;
    input.className = 'idaas-field__input';

    switch (field.field_type.toLowerCase()) {
        case 'email':
            input.type = 'email';
            input.autocomplete = 'email';
            break;
        case 'password':
            input.type = 'password';
            input.autocomplete = 'current-password';
            break;
        case 'phone':
            input.type = 'tel';
            input.autocomplete = 'tel';
            break;
        default:
            input.type = 'text';
    }

    wrapper.appendChild(label);
    wrapper.appendChild(input);
    container.appendChild(wrapper);

    return input;
}
