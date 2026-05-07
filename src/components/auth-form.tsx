"use client";

import Link from "next/link";
import { signIn } from "next-auth/react";
import { useRouter, useSearchParams } from "next/navigation";
import { useState, useTransition } from "react";
import { AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

type AuthFormProps = {
  mode: "signin" | "signup";
};

type OAuthProvider = "google" | "github";

export function AuthForm({ mode }: AuthFormProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const callbackUrl = searchParams.get("callbackUrl") ?? "/scans";
  const [error, setError] = useState<string | null>(null);
  const [oauthProvider, setOauthProvider] = useState<OAuthProvider | null>(null);
  const [isPending, startTransition] = useTransition();

  async function handleOAuthSignIn(provider: OAuthProvider) {
    setError(null);
    setOauthProvider(provider);

    try {
      await signIn(provider, { callbackUrl });
    } catch {
      setError("OAuth sign-in could not be started.");
      setOauthProvider(null);
    }
  }

  function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    const formData = new FormData(event.currentTarget);
    const email = String(formData.get("email") ?? "");
    const password = String(formData.get("password") ?? "");
    const name = String(formData.get("name") ?? "");

    startTransition(() => {
      void submit({ email, password, name, callbackUrl });
    });
  }

  async function submit(input: {
    email: string;
    password: string;
    name: string;
    callbackUrl: string;
  }) {
    try {
      if (mode === "signup") {
        const response = await fetch("/api/auth/register", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            email: input.email,
            password: input.password,
            name: input.name || undefined,
          }),
        });
        const payload = (await response.json().catch(() => null)) as {
          error?: string;
        } | null;

        if (!response.ok) {
          throw new Error(payload?.error ?? "Account creation failed.");
        }
      }

      const result = await signIn("credentials", {
        email: input.email,
        password: input.password,
        redirect: false,
      });

      if (result?.error) {
        throw new Error("Email or password is incorrect.");
      }

      router.push(input.callbackUrl);
      router.refresh();
    } catch (nextError) {
      setError(
        nextError instanceof Error
          ? nextError.message
          : "Authentication failed.",
      );
    }
  }

  return (
    <form className="space-y-4" onSubmit={handleSubmit}>
      {mode === "signin" ? (
        <>
          <div className="grid gap-3 sm:grid-cols-2">
            <Button
              type="button"
              variant="outline"
              className="gap-2"
              disabled={isPending || Boolean(oauthProvider)}
              onClick={() => void handleOAuthSignIn("google")}
            >
              <span className="font-semibold">G</span>
              {oauthProvider === "google" ? "Connecting..." : "Google"}
            </Button>
            <Button
              type="button"
              variant="outline"
              className="gap-2"
              disabled={isPending || Boolean(oauthProvider)}
              onClick={() => void handleOAuthSignIn("github")}
            >
              <span className="font-semibold">GH</span>
              {oauthProvider === "github" ? "Connecting..." : "GitHub"}
            </Button>
          </div>

          <div className="flex items-center gap-3 py-1">
            <div className="h-px flex-1 bg-line" />
            <span className="font-mono text-[10px] uppercase tracking-[0.24em] text-muted">
              or
            </span>
            <div className="h-px flex-1 bg-line" />
          </div>
        </>
      ) : null}

      {mode === "signup" ? (
        <div className="space-y-2">
          <label className="font-mono text-xs uppercase tracking-[0.24em] text-muted">
            Name
          </label>
          <Input name="name" placeholder="Your name" autoComplete="name" />
        </div>
      ) : null}

      <div className="space-y-2">
        <label className="font-mono text-xs uppercase tracking-[0.24em] text-muted">
          Email
        </label>
        <Input
          name="email"
          type="email"
          placeholder="you@example.com"
          autoComplete="email"
          required
        />
      </div>

      <div className="space-y-2">
        <label className="font-mono text-xs uppercase tracking-[0.24em] text-muted">
          Password
        </label>
        <Input
          name="password"
          type="password"
          placeholder="At least 8 characters"
          autoComplete={mode === "signup" ? "new-password" : "current-password"}
          minLength={8}
          required
        />
      </div>

      {error ? (
        <div className="flex items-start gap-3 rounded-2xl border border-danger/20 bg-danger/10 p-4 text-sm text-white">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-danger" />
          <p>{error}</p>
        </div>
      ) : null}

      <Button type="submit" className="w-full" disabled={isPending}>
        {isPending
          ? mode === "signup"
            ? "Creating account..."
            : "Signing in..."
          : mode === "signup"
            ? "Create account"
            : "Sign in"}
      </Button>

      <p className="text-center text-sm text-muted">
        {mode === "signup" ? "Already have an account?" : "New to CyberReflex?"}{" "}
        <Link
          href={mode === "signup" ? "/signin" : "/signup"}
          className="text-accent hover:text-white"
        >
          {mode === "signup" ? "Sign in" : "Create an account"}
        </Link>
      </p>
    </form>
  );
}
