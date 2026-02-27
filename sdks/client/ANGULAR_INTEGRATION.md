# IDaaS Angular Integration Guide

Complete guide for integrating IDaaS authentication into Angular applications.

## 📦 Installation

```bash
npm install @idaas/client
# or
yarn add @idaas/client
```

---

## 🚀 Quick Start

### 1. Create IDaaS Service

Create `src/app/services/idaas.service.ts`:

```typescript
import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';
import IDaaSClient from '@idaas/client';

export interface User {
  id: string;
  email: string;
  firstName?: string;
  lastName?: string;
  emailVerified: boolean;
}

@Injectable({
  providedIn: 'root'
})
export class IDaaSService {
  private client: IDaaSClient;
  private userSubject = new BehaviorSubject<User | null>(null);
  private loadingSubject = new BehaviorSubject<boolean>(true);

  public user$ = this.userSubject.asObservable();
  public loading$ = this.loadingSubject.asObservable();
  public isAuthenticated$ = new BehaviorSubject<boolean>(false);

  constructor() {
    // Initialize with publishable key
    this.client = new IDaaSClient({
      publishableKey: 'pk_test_yourinstance', // Use environment variable
    });

    // Check if user is already authenticated
    this.initializeAuth();
  }

  private async initializeAuth(): Promise<void> {
    try {
      const token = sessionStorage.getItem('jwt');
      if (token) {
        const user = await this.client.getCurrentUser();
        this.userSubject.next(user);
        this.isAuthenticated$.next(true);
      }
    } catch (error) {
      console.error('Auth initialization failed:', error);
      this.signOut();
    } finally {
      this.loadingSubject.next(false);
    }
  }

  async signIn(email: string, password: string): Promise<User> {
    try {
      const response = await this.client.signIn({ email, password });
      this.userSubject.next(response.user);
      this.isAuthenticated$.next(true);
      return response.user;
    } catch (error) {
      throw error;
    }
  }

  async signUp(email: string, password: string, firstName?: string, lastName?: string): Promise<User> {
    try {
      const response = await this.client.signUp({
        email,
        password,
        firstName,
        lastName,
      });
      this.userSubject.next(response.user);
      this.isAuthenticated$.next(true);
      return response.user;
    } catch (error) {
      throw error;
    }
  }

  async signOut(): Promise<void> {
    try {
      await this.client.signOut();
    } finally {
      this.userSubject.next(null);
      this.isAuthenticated$.next(false);
      sessionStorage.removeItem('jwt');
    }
  }

  async updateProfile(data: { firstName?: string; lastName?: string }): Promise<User> {
    const user = await this.client.updateProfile(data);
    this.userSubject.next(user);
    return user;
  }

  getCurrentUser(): User | null {
    return this.userSubject.value;
  }

  getToken(): string | null {
    return sessionStorage.getItem('jwt');
  }
}
```

---

### 2. Create Auth Guard

Create `src/app/guards/auth.guard.ts`:

```typescript
import { Injectable } from '@angular/core';
import { Router, CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { Observable } from 'rxjs';
import { map, take } from 'rxjs/operators';
import { IDaaSService } from '../services/idaas.service';

@Injectable({
  providedIn: 'root'
})
export class AuthGuard implements CanActivate {
  constructor(
    private idaasService: IDaaSService,
    private router: Router
  ) {}

  canActivate(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): Observable<boolean> {
    return this.idaasService.isAuthenticated$.pipe(
      take(1),
      map(isAuthenticated => {
        if (!isAuthenticated) {
          // Redirect to login with return URL
          this.router.navigate(['/login'], {
            queryParams: { returnUrl: state.url }
          });
          return false;
        }
        return true;
      })
    );
  }
}
```

---

### 3. Create HTTP Interceptor

Create `src/app/interceptors/auth.interceptor.ts`:

```typescript
import { Injectable } from '@angular/core';
import {
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpInterceptor,
  HttpErrorResponse
} from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';
import { Router } from '@angular/router';
import { IDaaSService } from '../services/idaas.service';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  constructor(
    private idaasService: IDaaSService,
    private router: Router
  ) {}

  intercept(request: HttpRequest<unknown>, next: HttpHandler): Observable<HttpEvent<unknown>> {
    // Add auth token to requests
    const token = this.idaasService.getToken();
    
    if (token) {
      request = request.clone({
        setHeaders: {
          Authorization: `Bearer ${token}`
        }
      });
    }

    return next.handle(request).pipe(
      catchError((error: HttpErrorResponse) => {
        if (error.status === 401) {
          // Token expired or invalid
          this.idaasService.signOut();
          this.router.navigate(['/login']);
        }
        return throwError(() => error);
      })
    );
  }
}
```

---

### 4. Configure App Module

Update `src/app/app.module.ts`:

```typescript
import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { HttpClientModule, HTTP_INTERCEPTORS } from '@angular/common/http';
import { ReactiveFormsModule } from '@angular/forms';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { IDaaSService } from './services/idaas.service';
import { AuthGuard } from './guards/auth.guard';
import { AuthInterceptor } from './interceptors/auth.interceptor';

@NgModule({
  declarations: [
    AppComponent,
    // Your components
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    HttpClientModule,
    ReactiveFormsModule,
  ],
  providers: [
    IDaaSService,
    AuthGuard,
    {
      provide: HTTP_INTERCEPTORS,
      useClass: AuthInterceptor,
      multi: true
    }
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
```

---

### 5. Configure Routes

Update `src/app/app-routing.module.ts`:

```typescript
import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { AuthGuard } from './guards/auth.guard';

const routes: Routes = [
  { path: '', redirectTo: '/dashboard', pathMatch: 'full' },
  { path: 'login', component: LoginComponent },
  { path: 'signup', component: SignupComponent },
  { 
    path: 'dashboard', 
    component: DashboardComponent,
    canActivate: [AuthGuard] // Protected route
  },
  { 
    path: 'profile', 
    component: ProfileComponent,
    canActivate: [AuthGuard] // Protected route
  },
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule]
})
export class AppRoutingModule { }
```

---

## 📝 Component Examples

### Login Component

`src/app/components/login/login.component.ts`:

```typescript
import { Component } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router, ActivatedRoute } from '@angular/router';
import { IDaaSService } from '../../services/idaas.service';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent {
  loginForm: FormGroup;
  loading = false;
  error: string | null = null;
  returnUrl: string;

  constructor(
    private fb: FormBuilder,
    private idaasService: IDaaSService,
    private router: Router,
    private route: ActivatedRoute
  ) {
    this.loginForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', [Validators.required, Validators.minLength(8)]]
    });

    // Get return URL from query params
    this.returnUrl = this.route.snapshot.queryParams['returnUrl'] || '/dashboard';
  }

  async onSubmit(): Promise<void> {
    if (this.loginForm.invalid) {
      return;
    }

    this.loading = true;
    this.error = null;

    try {
      const { email, password } = this.loginForm.value;
      await this.idaasService.signIn(email, password);
      
      // Redirect to return URL or dashboard
      this.router.navigateByUrl(this.returnUrl);
    } catch (error: any) {
      this.error = error.message || 'Login failed. Please try again.';
    } finally {
      this.loading = false;
    }
  }
}
```

`src/app/components/login/login.component.html`:

```html
<div class="login-container">
  <h2>Sign In</h2>
  
  <form [formGroup]="loginForm" (ngSubmit)="onSubmit()">
    <!-- Error Message -->
    <div *ngIf="error" class="error-message">
      {{ error }}
    </div>

    <!-- Email Field -->
    <div class="form-group">
      <label for="email">Email</label>
      <input
        id="email"
        type="email"
        formControlName="email"
        placeholder="you@example.com"
        [class.invalid]="loginForm.get('email')?.invalid && loginForm.get('email')?.touched"
      />
      <div *ngIf="loginForm.get('email')?.invalid && loginForm.get('email')?.touched" class="field-error">
        Please enter a valid email
      </div>
    </div>

    <!-- Password Field -->
    <div class="form-group">
      <label for="password">Password</label>
      <input
        id="password"
        type="password"
        formControlName="password"
        placeholder="••••••••"
        [class.invalid]="loginForm.get('password')?.invalid && loginForm.get('password')?.touched"
      />
      <div *ngIf="loginForm.get('password')?.invalid && loginForm.get('password')?.touched" class="field-error">
        Password must be at least 8 characters
      </div>
    </div>

    <!-- Submit Button -->
    <button type="submit" [disabled]="loading || loginForm.invalid">
      <span *ngIf="!loading">Sign In</span>
      <span *ngIf="loading">Signing in...</span>
    </button>

    <!-- Sign Up Link -->
    <p class="signup-link">
      Don't have an account? <a routerLink="/signup">Sign up</a>
    </p>
  </form>
</div>
```

---

### Dashboard Component

`src/app/components/dashboard/dashboard.component.ts`:

```typescript
import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { IDaaSService, User } from '../../services/idaas.service';

@Component({
  selector: 'app-dashboard',
  templateUrl: './dashboard.component.html',
  styleUrls: ['./dashboard.component.css']
})
export class DashboardComponent implements OnInit {
  user: User | null = null;

  constructor(
    public idaasService: IDaaSService,
    private router: Router
  ) {}

  ngOnInit(): void {
    // Subscribe to user changes
    this.idaasService.user$.subscribe(user => {
      this.user = user;
    });
  }

  async signOut(): Promise<void> {
    await this.idaasService.signOut();
    this.router.navigate(['/login']);
  }
}
```

`src/app/components/dashboard/dashboard.component.html`:

```html
<div class="dashboard">
  <header>
    <h1>Dashboard</h1>
    <div class="user-menu">
      <span *ngIf="user">{{ user.email }}</span>
      <button (click)="signOut()">Sign Out</button>
    </div>
  </header>

  <main>
    <div *ngIf="user" class="welcome">
      <h2>Welcome, {{ user.firstName || user.email }}!</h2>
      <p>Email: {{ user.email }}</p>
      <p>Status: {{ user.emailVerified ? 'Verified' : 'Unverified' }}</p>
    </div>

    <!-- Your dashboard content -->
  </main>
</div>
```

---

## 🔒 User Button Component

Create a reusable user menu component:

`src/app/components/user-button/user-button.component.ts`:

```typescript
import { Component } from '@angular/core';
import { Router } from '@angular/router';
import { IDaaSService } from '../../services/idaas.service';

@Component({
  selector: 'app-user-button',
  templateUrl: './user-button.component.html',
  styleUrls: ['./user-button.component.css']
})
export class UserButtonComponent {
  showMenu = false;

  constructor(
    public idaasService: IDaaSService,
    private router: Router
  ) {}

  toggleMenu(): void {
    this.showMenu = !this.showMenu;
  }

  async signOut(): Promise<void> {
    await this.idaasService.signOut();
    this.router.navigate(['/login']);
    this.showMenu = false;
  }
}
```

`src/app/components/user-button/user-button.component.html`:

```html
<div class="user-button" *ngIf="idaasService.user$ | async as user">
  <button (click)="toggleMenu()" class="avatar-button">
    <div class="avatar">
      {{ user.email[0].toUpperCase() }}
    </div>
    <span>{{ user.firstName || user.email.split('@')[0] }}</span>
  </button>

  <div *ngIf="showMenu" class="dropdown-menu">
    <div class="user-info">
      <strong>{{ user.email }}</strong>
      <span>{{ user.emailVerified ? '✓ Verified' : 'Unverified' }}</span>
    </div>
    
    <div class="menu-items">
      <a routerLink="/profile" (click)="toggleMenu()">Profile</a>
      <a routerLink="/settings" (click)="toggleMenu()">Settings</a>
      <button (click)="signOut()">Sign Out</button>
    </div>
  </div>
</div>
```

---

## 🎨 Styling Example

`user-button.component.css`:

```css
.user-button {
  position: relative;
}

.avatar-button {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border: none;
  background: transparent;
  cursor: pointer;
}

.avatar {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: bold;
}

.dropdown-menu {
  position: absolute;
  top: 100%;
  right: 0;
  margin-top: 8px;
  background: white;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
  min-width: 200px;
  z-index: 1000;
}

.user-info {
  padding: 12px;
  border-bottom: 1px solid #e2e8f0;
}

.menu-items a, .menu-items button {
  display: block;
  padding: 8px 12px;
  text-decoration: none;
  color: #334155;
  border: none;
  background: none;
  width: 100%;
  text-align: left;
  cursor: pointer;
}

.menu-items a:hover, .menu-items button:hover {
  background: #f1f5f9;
}
```

---

## 🌍 Environment Configuration

`src/environments/environment.ts`:

```typescript
export const environment = {
  production: false,
  idaas: {
    publishableKey: 'pk_test_yourinstance'
  }
};
```

`src/environments/environment.prod.ts`:

```typescript
export const environment = {
  production: true,
  idaas: {
    publishableKey: 'pk_live_yourinstance'
  }
};
```

Update the service to use environment:

```typescript
import { environment } from '../../environments/environment';

this.client = new IDaaSClient({
  publishableKey: environment.idaas.publishableKey,
});
```

---

## 🎯 Advanced: Structural Directive

Create `*requireAuth` directive for conditional rendering:

`src/app/directives/require-auth.directive.ts`:

```typescript
import { Directive, TemplateRef, ViewContainerRef, OnInit } from '@angular/core';
import { IDaaSService } from '../services/idaas.service';

@Directive({
  selector: '[requireAuth]'
})
export class RequireAuthDirective implements OnInit {
  constructor(
    private templateRef: TemplateRef<any>,
    private viewContainer: ViewContainerRef,
    private idaasService: IDaaSService
  ) {}

  ngOnInit(): void {
    this.idaasService.isAuthenticated$.subscribe(isAuthenticated => {
      if (isAuthenticated) {
        this.viewContainer.createEmbeddedView(this.templateRef);
      } else {
        this.viewContainer.clear();
      }
    });
  }
}
```

Usage:

```html
<div *requireAuth>
  This content is only visible to authenticated users
</div>
```

---

## 📦 Complete File Structure

```
src/app/
├── services/
│   └── idaas.service.ts
├── guards/
│   └── auth.guard.ts
├── interceptors/
│   └── auth.interceptor.ts
├── directives/
│   └── require-auth.directive.ts
├── components/
│   ├── login/
│   ├── signup/
│   ├── dashboard/
│   └── user-button/
└── app.module.ts
```

---

## 🚀 Usage Summary

**1. Wrap your app:**
- Configure IDaaSService with publishable key
- Add AuthInterceptor to automatically attach tokens
- Use AuthGuard on protected routes

**2. In components:**
```typescript
// Check if user is authenticated
this.idaasService.isAuthenticated$.subscribe(...)

// Get current user
this.idaasService.user$.subscribe(user => ...)

// Sign in
await this.idaasService.signIn(email, password)

// Sign out
await this.idaasService.signOut()
```

**3. In templates:**
```html
<!-- Conditional rendering -->
<div *ngIf="idaasService.isAuthenticated$ | async">
  Authenticated content
</div>

<!-- User button -->
<app-user-button></app-user-button>
```

That's it! Your Angular app is now integrated with IDaaS! 🎉
