# Angular Integration - Quick Reference

## Installation
```bash
npm install @idaas/client
```

## Basic Setup

### 1. Service (idaas.service.ts)
```typescript
import IDaaSClient from '@idaas/client';

@Injectable({ providedIn: 'root' })
export class IDaaSService {
  private client = new IDaaSClient({
    publishableKey: 'pk_test_yourinstance'
  });
  
  user$ = new BehaviorSubject<User | null>(null);
  isAuthenticated$ = new BehaviorSubject<boolean>(false);
  
  signIn(email: string, password: string) {
    return this.client.signIn({ email, password });
  }
}
```

### 2. Guard (auth.guard.ts)
```typescript
@Injectable({ providedIn: 'root' })
export class AuthGuard implements CanActivate {
  canActivate() {
    return this.idaasService.isAuthenticated$;
  }
}
```

### 3. Routes
```typescript
const routes = [
  { path: 'dashboard', component: DashboardComponent, canActivate: [AuthGuard] }
];
```

## Component Usage

```typescript
export class LoginComponent {
  constructor(private idaas: IDaaSService) {}
  
  async onSubmit() {
    await this.idaas.signIn(email, password);
    this.router.navigate(['/dashboard']);
  }
}
```

## Template Usage

```html
<div *ngIf="idaas.isAuthenticated$ | async">
  <p>Welcome {{ (idaas.user$ | async)?.email }}</p>
  <button (click)="idaas.signOut()">Sign Out</button>
</div>
```

See [ANGULAR_INTEGRATION.md](./ANGULAR_INTEGRATION.md) for full documentation.
