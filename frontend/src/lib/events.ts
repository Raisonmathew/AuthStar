
// Custom Event Types
export const AUTH_STEP_UP_REQUIRED = 'auth:step-up-required';
export const AUTH_STEP_UP_COMPLETE = 'auth:step-up-complete';
export const AUTH_STEP_UP_CANCELLED = 'auth:step-up-cancelled';

import { Requirement } from './types';

export interface StepUpRequiredEvent extends CustomEvent {
    detail: {
        originalRequestConfig?: any;
        requirement?: Requirement;
        // The following properties are inferred from the user's intended change
        // and are added to make the interface syntactically correct.
        // The original change provided executable code within an interface,
        // which is not valid. These are interpreted as properties of the detail object.
        originalRequest?: { _retry?: boolean };
        isSteppingUp?: boolean;
    };
}

export function dispatchStepUpRequired(config?: any, requirement?: Requirement) {
    window.dispatchEvent(new CustomEvent(AUTH_STEP_UP_REQUIRED, { detail: { originalRequestConfig: config, requirement } }));
}

export function dispatchStepUpComplete() {
    window.dispatchEvent(new Event(AUTH_STEP_UP_COMPLETE));
}

export function dispatchStepUpCancelled() {
    window.dispatchEvent(new Event(AUTH_STEP_UP_CANCELLED));
}
