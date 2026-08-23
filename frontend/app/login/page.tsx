"use client";

import { useState, type FormEvent } from "react";
import { useAuth } from "@/lib/auth-context";

export default function LoginPage() {
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(email, password);
    } catch {
      setError("Invalid email or password.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-base-950 px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex items-center justify-center gap-2">
          <span className="font-mono text-2xl font-bold text-signal-500">SG</span>
          <span className="text-lg font-semibold text-ink-100">SentinelGuard</span>
        </div>

        <form
          onSubmit={handleSubmit}
          className="rounded-lg border border-base-600 bg-base-800 p-6 shadow-panel"
        >
          <h1 className="mb-5 text-sm font-medium text-ink-300">Sign in to your dashboard</h1>

          <label className="mb-1 block text-xs text-ink-500" htmlFor="email">
            Email
          </label>
          <input
            id="email"
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="mb-4 w-full rounded-md border border-base-600 bg-base-900 px-3 py-2 text-sm text-ink-100 outline-none focus:border-signal-500"
            placeholder="admin@example.com"
          />

          <label className="mb-1 block text-xs text-ink-500" htmlFor="password">
            Password
          </label>
          <input
            id="password"
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="mb-5 w-full rounded-md border border-base-600 bg-base-900 px-3 py-2 text-sm text-ink-100 outline-none focus:border-signal-500"
            placeholder="••••••••"
          />

          {error && (
            <p className="mb-4 rounded-md border border-severity-critical/30 bg-severity-critical/10 px-3 py-2 text-xs text-severity-critical">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="w-full rounded-md bg-signal-500 px-3 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-signal-400 disabled:opacity-60"
          >
            {submitting ? "Signing in…" : "Sign in"}
          </button>
        </form>

        <p className="mt-4 text-center text-xs text-ink-700">
          First run? Register your admin account via{" "}
          <code className="font-mono text-ink-500">POST /api/v1/auth/register</code>
        </p>
      </div>
    </div>
  );
}
