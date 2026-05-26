# Google OAuth2 — Next.js Integration Guide

## 1. Install the package

```bash
npm install @react-oauth/google
```

---

## 2. Wrap your app  (`app/layout.tsx` or `pages/_app.tsx`)

```tsx
// app/layout.tsx  (Next.js 13+ App Router)
import { GoogleOAuthProvider } from "@react-oauth/google";

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html>
      <body>
        <GoogleOAuthProvider clientId={process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID!}>
          {children}
        </GoogleOAuthProvider>
      </body>
    </html>
  );
}
```

Add to `.env.local`:
```
NEXT_PUBLIC_GOOGLE_CLIENT_ID=594436129615-mgr2jbkt74v0n5ccj4n01dpe5q9i6bhb.apps.googleusercontent.com
NEXT_PUBLIC_API_URL=http://localhost:8000/api
```

---

## 3. Google Sign-In button component

```tsx
// components/GoogleSignInButton.tsx
"use client";

import { GoogleLogin, CredentialResponse } from "@react-oauth/google";
import { useRouter } from "next/navigation";

export function GoogleSignInButton() {
  const router = useRouter();

  const handleSuccess = async (credentialResponse: CredentialResponse) => {
    if (!credentialResponse.credential) return;

    try {
      const res = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/auth/google/`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ credential: credentialResponse.credential }),
        }
      );

      if (!res.ok) {
        const error = await res.json();
        throw new Error(error.detail ?? "Google sign-in failed");
      }

      const data = await res.json();

      // ── Store tokens ─────────────────────────────────────────────────────
      // Option A (simpler): localStorage — acceptable for SPAs without SSR
      localStorage.setItem("access_token",  data.access);
      localStorage.setItem("refresh_token", data.refresh);

      // Option B (more secure): httpOnly cookies via a /api/auth/session
      // route handler in Next.js that sets the cookie server-side.

      router.push("/dashboard");
    } catch (err) {
      console.error("Google OAuth error:", err);
    }
  };

  return (
    <GoogleLogin
      onSuccess={handleSuccess}
      onError={() => console.error("Google Login Failed")}
      useOneTap          // optional: shows the Google One Tap prompt
      auto_select={false}
    />
  );
}
```

---

## 4. Axios interceptor for attaching the access token

```ts
// lib/api.ts
import axios from "axios";

const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL,
});

// Attach access token to every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("access_token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// Auto-refresh on 401
api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const original = error.config;
    if (error.response?.status === 401 && !original._retry) {
      original._retry = true;
      const refresh = localStorage.getItem("refresh_token");
      if (refresh) {
        try {
          const { data } = await axios.post(
            `${process.env.NEXT_PUBLIC_API_URL}/auth/token/refresh/`,
            { refresh }
          );
          localStorage.setItem("access_token",  data.access);
          localStorage.setItem("refresh_token", data.refresh);
          original.headers.Authorization = `Bearer ${data.access}`;
          return api(original);
        } catch {
          // Refresh failed → redirect to login
          localStorage.clear();
          window.location.href = "/login";
        }
      }
    }
    return Promise.reject(error);
  }
);

export default api;
```

---

## 5. Logout

```ts
// Call the backend to revoke the session, then clear local tokens
async function logout() {
  const refresh = localStorage.getItem("refresh_token");
  if (refresh) {
    await api.post("/auth/logout/", { refresh }).catch(() => {});
  }
  localStorage.removeItem("access_token");
  localStorage.removeItem("refresh_token");
  window.location.href = "/login";
}
```

---

## 6. Google Cloud Console checklist

1. Go to **APIs & Services → Credentials → OAuth 2.0 Client IDs**.
2. Add **Authorised JavaScript origins**:
   - `http://localhost:3000`  (development)
   - `https://yourdomain.com` (production)
3. Add **Authorised redirect URIs** (only needed for server-side flow; not required here):
   - `http://localhost:3000/auth/callback`
4. Enable the **Google+ API** or **People API** if you need additional profile fields.

---

## 7. Backend endpoint summary

| Method | URL | Description |
|--------|-----|-------------|
| POST | `/api/auth/google/` | Exchange Google ID token for JWT pair |
| POST | `/api/auth/register/` | Email + password registration |
| POST | `/api/auth/verify-email/` | Email verification |
| POST | `/api/auth/login/` | Email + password login |
| POST | `/api/auth/logout/` | Revoke session |
| POST | `/api/auth/token/refresh/` | Refresh access token |
| POST | `/api/auth/magic-link/request/` | Send magic link |
| POST | `/api/auth/magic-link/verify/` | Consume magic link |
| POST | `/api/auth/password-reset/request/` | Send reset email |
| POST | `/api/auth/password-reset/confirm/` | Set new password |
| GET  | `/api/auth/me/` | Get current user profile |
| PATCH | `/api/auth/me/update/` | Update profile |
| POST | `/api/auth/me/change-password/` | Change password |
| GET  | `/api/auth/sessions/` | List active sessions |
| DELETE | `/api/auth/sessions/<id>/revoke/` | Revoke a session |