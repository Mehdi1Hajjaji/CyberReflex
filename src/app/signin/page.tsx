import { Shield } from "lucide-react";
import { Suspense } from "react";
import { connection } from "next/server";
import { enabledOAuthProviders } from "@/auth";
import { AuthForm } from "@/components/auth-form";
import { Card, CardContent } from "@/components/ui/card";

export default async function SignInPage() {
  await connection();

  return (
    <main className="relative z-10 flex min-h-screen items-center justify-center px-5 py-10">
      <Card className="glass-panel terminal-edge w-full max-w-md">
        <CardContent className="p-6 md:p-8">
          <div className="mb-7 flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-2xl border border-accent/25 bg-accent/10 text-accent">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <div className="font-mono text-xs uppercase tracking-[0.34em] text-accent/80">
                cyberreflex
              </div>
              <h1 className="text-2xl font-semibold text-white">Sign in</h1>
            </div>
          </div>

          <Suspense fallback={null}>
            <AuthForm
              mode="signin"
              enabledOAuthProviders={enabledOAuthProviders}
            />
          </Suspense>
        </CardContent>
      </Card>
    </main>
  );
}
