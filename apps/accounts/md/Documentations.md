# Frontend Integration Documentation — Next.js Auth System

## 1. Backend Base URL

Use this environment variable in Next.js:

```env
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
```

If backend routes are under `/api/`, then use:

```env
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000/api
```

All endpoints below assume:

```ts
const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL;
```

---

# 2. Authentication Overview

The backend uses JWT authentication.

After login/register magic-link/Google login, backend returns:

```json
{
  "success": true,
  "message": "Login successful.",
  "access": "ACCESS_TOKEN",
  "refresh": "REFRESH_TOKEN",
  "access_expires_at": "2026-06-08T10:00:00Z"
}
```

Frontend should store:

```ts
accessToken
refreshToken
```

Recommended storage:

For simple frontend:

```ts
localStorage.setItem("access", access);
localStorage.setItem("refresh", refresh);
```

For production security:

Use httpOnly cookies through a Next.js API route.

---

# 3. API Helper

Create:

```ts
// lib/api.ts

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL;

export async function apiRequest(
  path: string,
  options: RequestInit = {}
) {
  const accessToken =
    typeof window !== "undefined"
      ? localStorage.getItem("access")
      : null;

  const headers: HeadersInit = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };

  if (accessToken) {
    headers["Authorization"] = `Bearer ${accessToken}`;
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers,
  });

  const data = await response.json().catch(() => null);

  if (!response.ok) {
    throw data || { message: "Something went wrong" };
  }

  return data;
}
```

---

# 4. Register User

Endpoint:

```http
POST /auth/register/
```

Request:

```json
{
  "email": "user@example.com",
  "full_name": "John Doe",
  "password": "StrongPass123!",
  "password_confirm": "StrongPass123!",
  "terms_accepted": true
}
```

Example:

```ts
export async function registerUser(payload: {
  email: string;
  full_name: string;
  password: string;
  password_confirm: string;
  terms_accepted: boolean;
}) {
  return apiRequest("/auth/register/", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}
```

Success response:

```json
{
  "success": true,
  "message": "Account created. Please check your email to verify your address.",
  "user_id": "uuid",
  "email": "user@example.com"
}
```

After registration, show:

```text
Account created. Please check your email to verify your address.
```

---

# 5. Verify Email

Backend sends email link like:

```text
/frontend/auth/verify-email?token=RAW_TOKEN
```

Next.js page should read token from URL and call backend.

Endpoint:

```http
POST /auth/verify-email/
```

Request:

```json
{
  "token": "RAW_TOKEN_FROM_URL"
}
```

Example Next.js page logic:

```ts
export async function verifyEmail(token: string) {
  return apiRequest("/auth/verify-email/", {
    method: "POST",
    body: JSON.stringify({ token }),
  });
}
```

Success response:

```json
{
  "success": true,
  "message": "Email verified successfully. You may now log in."
}
```

---

# 6. Login

Endpoint:

```http
POST /auth/login/
```

Request:

```json
{
  "email": "user@example.com",
  "password": "StrongPass123!"
}
```

Example:

```ts
export async function loginUser(payload: {
  email: string;
  password: string;
}) {
  const data = await apiRequest("/auth/login/", {
    method: "POST",
    body: JSON.stringify(payload),
  });

  localStorage.setItem("access", data.access);
  localStorage.setItem("refresh", data.refresh);

  return data;
}
```

Success response:

```json
{
  "success": true,
  "message": "Login successful.",
  "access": "ACCESS_TOKEN",
  "refresh": "REFRESH_TOKEN",
  "access_expires_at": "2026-06-08T10:00:00Z"
}
```

Possible errors:

```json
{
  "non_field_errors": ["Incorrect password."]
}
```

```json
{
  "non_field_errors": ["Please verify your email address before logging in."]
}
```

---

# 7. Get Current User

Endpoint:

```http
GET /auth/me/
```

Requires:

```http
Authorization: Bearer ACCESS_TOKEN
```

Example:

```ts
export async function getMe() {
  return apiRequest("/auth/me/", {
    method: "GET",
  });
}
```

Response:

```json
{
  "id": "uuid",
  "email": "user@example.com",
  "full_name": "John Doe",
  "role": "Client",
  "is_email_verified": true,
  "is_oauth_user": false,
  "google_picture_url": "",
  "tenant": null,
  "terms_accepted_at": "2026-06-08T10:00:00Z",
  "created_at": "2026-06-08T10:00:00Z",
  "profile": {
    "date_of_birth": null,
    "phone_number": null,
    "alternate_email": null,
    "address_line1": "",
    "address_line2": "",
    "city": "",
    "state_province": "",
    "postal_code": "",
    "country": "",
    "profile_picture": null,
    "bio": "",
    "preferences": {},
    "timezone": "UTC",
    "language": "en",
    "updated_at": "2026-06-08T10:00:00Z"
  }
}
```

---

# 8. Update Current User

Endpoint:

```http
PATCH /auth/me/update/
```

Requires auth.

Request:

```json
{
  "full_name": "Updated Name",
  "privacy_accepted_version": "v1",
  "profile": {
    "city": "Kabul",
    "country": "AF",
    "bio": "Hello world"
  }
}
```

Example:

```ts
export async function updateMe(payload: {
  full_name?: string;
  privacy_accepted_version?: string;
  profile?: {
    date_of_birth?: string | null;
    phone_number?: string | null;
    alternate_email?: string | null;
    address_line1?: string;
    address_line2?: string;
    city?: string;
    state_province?: string;
    postal_code?: string;
    country?: string;
    bio?: string;
    preferences?: Record<string, any>;
    timezone?: string;
    language?: string;
  };
}) {
  return apiRequest("/auth/me/update/", {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}
```

---

# 9. Refresh Token

Endpoint:

```http
POST /auth/token/refresh/
```

Request:

```json
{
  "refresh": "REFRESH_TOKEN"
}
```

Example:

```ts
export async function refreshToken() {
  const refresh = localStorage.getItem("refresh");

  if (!refresh) {
    throw new Error("No refresh token found");
  }

  const data = await apiRequest("/auth/token/refresh/", {
    method: "POST",
    body: JSON.stringify({ refresh }),
  });

  localStorage.setItem("access", data.access);
  localStorage.setItem("refresh", data.refresh);

  return data;
}
```

Response:

```json
{
  "success": true,
  "access": "NEW_ACCESS_TOKEN",
  "refresh": "NEW_REFRESH_TOKEN",
  "access_expires_at": "2026-06-08T10:15:00Z"
}
```

Important:

When refresh succeeds, replace both old tokens with the new tokens.

---

# 10. Auto Refresh on 401

Use this helper for authenticated requests:

```ts
export async function authRequest(path: string, options: RequestInit = {}) {
  try {
    return await apiRequest(path, options);
  } catch (error: any) {
    const isUnauthorized =
      error?.detail?.includes("token") ||
      error?.code === "token_not_valid";

    if (!isUnauthorized) {
      throw error;
    }

    await refreshToken();

    return apiRequest(path, options);
  }
}
```

Use `authRequest()` for protected pages.

---

# 11. Logout

Endpoint:

```http
POST /auth/logout/
```

Requires auth.

Request:

```json
{
  "refresh": "REFRESH_TOKEN"
}
```

Example:

```ts
export async function logoutUser() {
  const refresh = localStorage.getItem("refresh");

  if (refresh) {
    try {
      await apiRequest("/auth/logout/", {
        method: "POST",
        body: JSON.stringify({ refresh }),
      });
    } catch {
      // ignore logout API errors
    }
  }

  localStorage.removeItem("access");
  localStorage.removeItem("refresh");
}
```

After logout, redirect user to:

```text
/login
```

---

# 12. Magic Link Login

## Request Magic Link

Endpoint:

```http
POST /auth/magic-link/request/
```

Request:

```json
{
  "email": "user@example.com"
}
```

Example:

```ts
export async function requestMagicLink(email: string) {
  return apiRequest("/auth/magic-link/request/", {
    method: "POST",
    body: JSON.stringify({ email }),
  });
}
```

Response always looks successful:

```json
{
  "success": true,
  "message": "If that email is registered you will receive a sign-in link shortly."
}
```

## Verify Magic Link

Backend email link should open frontend page:

```text
/auth/magic-link?token=RAW_TOKEN
```

Frontend reads token and calls:

```http
POST /auth/magic-link/verify/
```

Request:

```json
{
  "token": "RAW_TOKEN"
}
```

Example:

```ts
export async function verifyMagicLink(token: string) {
  const data = await apiRequest("/auth/magic-link/verify/", {
    method: "POST",
    body: JSON.stringify({ token }),
  });

  localStorage.setItem("access", data.access);
  localStorage.setItem("refresh", data.refresh);

  return data;
}
```

---

# 13. Password Reset

## Request Password Reset

Endpoint:

```http
POST /auth/password-reset/request/
```

Request:

```json
{
  "email": "user@example.com"
}
```

Example:

```ts
export async function requestPasswordReset(email: string) {
  return apiRequest("/auth/password-reset/request/", {
    method: "POST",
    body: JSON.stringify({ email }),
  });
}
```

Response:

```json
{
  "success": true,
  "message": "If that email is registered you will receive a password-reset link."
}
```

## Confirm Password Reset

Backend email link should open frontend page:

```text
/auth/reset-password?token=RAW_TOKEN
```

Frontend reads token and submits new password.

Endpoint:

```http
POST /auth/password-reset/confirm/
```

Request:

```json
{
  "token": "RAW_TOKEN",
  "password": "NewStrongPass123!",
  "password_confirm": "NewStrongPass123!"
}
```

Example:

```ts
export async function confirmPasswordReset(payload: {
  token: string;
  password: string;
  password_confirm: string;
}) {
  return apiRequest("/auth/password-reset/confirm/", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}
```

Success response:

```json
{
  "success": true,
  "message": "Password updated successfully. Please log in."
}
```

---

# 14. Change Password

Endpoint:

```http
POST /auth/me/change-password/
```

Requires auth.

Request:

```json
{
  "current_password": "OldStrongPass123!",
  "new_password": "NewStrongPass123!",
  "new_password_confirm": "NewStrongPass123!",
  "current_refresh": "CURRENT_REFRESH_TOKEN"
}
```

Example:

```ts
export async function changePassword(payload: {
  current_password: string;
  new_password: string;
  new_password_confirm: string;
}) {
  const current_refresh = localStorage.getItem("refresh");

  return apiRequest("/auth/me/change-password/", {
    method: "POST",
    body: JSON.stringify({
      ...payload,
      current_refresh,
    }),
  });
}
```

Success response:

```json
{
  "success": true,
  "message": "Password changed successfully."
}
```

After password change, you can either:

1. keep current user logged in if backend preserved current refresh token, or
2. logout and ask user to login again.

Recommended frontend behavior:

```ts
await changePassword(payload);
await logoutUser();
router.push("/login");
```

---

# 15. Active Sessions

Endpoint:

```http
GET /auth/sessions/
```

Requires auth.

Example:

```ts
export async function getActiveSessions() {
  return apiRequest("/auth/sessions/", {
    method: "GET",
  });
}
```

Expected response:

```json
{
  "sessions": [
    {
      "id": "uuid",
      "device_name": "Chrome Browser",
      "ip_address": "127.0.0.1",
      "last_used_at": "2026-06-08T10:00:00Z",
      "created_at": "2026-06-08T09:00:00Z",
      "expires_at": "2026-06-09T09:00:00Z"
    }
  ]
}
```

---

# 16. Revoke Session

Endpoint:

```http
DELETE /auth/sessions/:session_id/revoke/
```

Requires auth.

Example:

```ts
export async function revokeSession(sessionId: string) {
  return apiRequest(`/auth/sessions/${sessionId}/revoke/`, {
    method: "DELETE",
  });
}
```

Use this for “Log out this device” or “Revoke session”.

---

# 17. Google OAuth Login

Install package:

```bash
npm install @react-oauth/google
```

Wrap app:

```tsx
// app/providers.tsx

"use client";

import { GoogleOAuthProvider } from "@react-oauth/google";

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <GoogleOAuthProvider clientId={process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID!}>
      {children}
    </GoogleOAuthProvider>
  );
}
```

Use in layout:

```tsx
// app/layout.tsx

import { Providers } from "./providers";

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
```

Google login button:

```tsx
"use client";

import { GoogleLogin } from "@react-oauth/google";

export function GoogleLoginButton() {
  async function handleGoogleSuccess(response: any) {
    const credential = response.credential;

    const data = await apiRequest("/auth/google/", {
      method: "POST",
      body: JSON.stringify({ credential }),
    });

    localStorage.setItem("access", data.access);
    localStorage.setItem("refresh", data.refresh);

    window.location.href = "/dashboard";
  }

  return (
    <GoogleLogin
      onSuccess={handleGoogleSuccess}
      onError={() => {
        alert("Google login failed");
      }}
    />
  );
}
```

Backend endpoint:

```http
POST /auth/google/
```

Request:

```json
{
  "credential": "GOOGLE_ID_TOKEN"
}
```

Success response:

```json
{
  "success": true,
  "message": "Google sign-in successful.",
  "access": "ACCESS_TOKEN",
  "refresh": "REFRESH_TOKEN",
  "access_expires_at": "2026-06-08T10:00:00Z"
}
```

---

# 18. Recommended Auth Context

Create:

```tsx
// contexts/AuthContext.tsx

"use client";

import {
  createContext,
  useContext,
  useEffect,
  useState,
} from "react";

type User = {
  id: string;
  email: string;
  full_name: string;
  role: string;
  is_email_verified: boolean;
  profile: any;
};

type AuthContextValue = {
  user: User | null;
  loading: boolean;
  reloadUser: () => Promise<void>;
  logout: () => Promise<void>;
};

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  async function reloadUser() {
    try {
      const data = await authRequest("/auth/me/");
      setUser(data);
    } catch {
      setUser(null);
    }
  }

  async function logout() {
    await logoutUser();
    setUser(null);
  }

  useEffect(() => {
    reloadUser().finally(() => setLoading(false));
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, reloadUser, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error("useAuth must be used inside AuthProvider");
  }

  return context;
}
```

---

# 19. Protected Page Example

```tsx
"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { useAuth } from "@/contexts/AuthContext";

export default function DashboardPage() {
  const router = useRouter();
  const { user, loading } = useAuth();

  useEffect(() => {
    if (!loading && !user) {
      router.push("/login");
    }
  }, [loading, user, router]);

  if (loading) {
    return <p>Loading...</p>;
  }

  if (!user) {
    return null;
  }

  return (
    <div>
      <h1>Welcome, {user.full_name}</h1>
      <p>Email: {user.email}</p>
      <p>Role: {user.role}</p>
    </div>
  );
}
```

---

# 20. Error Handling Format

DRF validation errors may return:

```json
{
  "email": ["This field is required."]
}
```

or:

```json
{
  "non_field_errors": ["Incorrect password."]
}
```

or:

```json
{
  "detail": "Authentication credentials were not provided."
}
```

Frontend helper:

```ts
export function getErrorMessage(error: any): string {
  if (!error) return "Something went wrong";

  if (typeof error === "string") return error;

  if (error.message) return error.message;
  if (error.detail) return error.detail;

  if (error.non_field_errors?.length) {
    return error.non_field_errors[0];
  }

  const firstKey = Object.keys(error)[0];

  if (firstKey && Array.isArray(error[firstKey])) {
    return error[firstKey][0];
  }

  return "Something went wrong";
}
```

---

# 21. Suggested Frontend Pages

Create these pages:

```text
/register
/login
/auth/verify-email
/auth/magic-link
/auth/reset-password
/forgot-password
/profile
/security/sessions
/dashboard
```

---

# 22. Full Endpoint Summary

| Feature                | Method | Endpoint                             | Auth Required |
| ---------------------- | -----: | ------------------------------------ | ------------: |
| Register               |   POST | `/auth/register/`                    |            No |
| Verify Email           |   POST | `/auth/verify-email/`                |            No |
| Login                  |   POST | `/auth/login/`                       |            No |
| Logout                 |   POST | `/auth/logout/`                      |           Yes |
| Refresh Token          |   POST | `/auth/token/refresh/`               |            No |
| Magic Link Request     |   POST | `/auth/magic-link/request/`          |            No |
| Magic Link Verify      |   POST | `/auth/magic-link/verify/`           |            No |
| Password Reset Request |   POST | `/auth/password-reset/request/`      |            No |
| Password Reset Confirm |   POST | `/auth/password-reset/confirm/`      |            No |
| Google OAuth           |   POST | `/auth/google/`                      |            No |
| Get Me                 |    GET | `/auth/me/`                          |           Yes |
| Update Me              |  PATCH | `/auth/me/update/`                   |           Yes |
| Change Password        |   POST | `/auth/me/change-password/`          |           Yes |
| Active Sessions        |    GET | `/auth/sessions/`                    |           Yes |
| Revoke Session         | DELETE | `/auth/sessions/:session_id/revoke/` |           Yes |

---

# 23. Implementation Order for Frontend Engineer

Recommended order:

1. Create API helper.
2. Build register page.
3. Build login page.
4. Store access/refresh tokens.
5. Build `/auth/me/` user loading.
6. Add protected route logic.
7. Add refresh token logic.
8. Add logout.
9. Add email verification page.
10. Add forgot/reset password.
11. Add magic link login.
12. Add Google OAuth.
13. Add profile update page.
14. Add active sessions page.

---

# 24. Important Notes

1. Always send access token like this:

```http
Authorization: Bearer ACCESS_TOKEN
```

2. Refresh token should only be sent to:

```text
/auth/token/refresh/
/auth/logout/
/auth/me/change-password/
```

3. When refresh token returns new tokens, replace old tokens.

4. If refresh fails, clear tokens and redirect to login.

5. Magic link and password reset tokens come from URL query params.

6. Google OAuth sends `credential`, not access token, to backend.

7. Register does not log user in automatically. User must verify email and then login.

8. Password reset logs out existing sessions on backend, so user should login again.

9. Use `getErrorMessage()` to display DRF errors nicely.

10. For production, prefer httpOnly cookies instead of localStorage.
