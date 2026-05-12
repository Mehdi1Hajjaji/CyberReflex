import { PrismaAdapter } from "@auth/prisma-adapter";
import NextAuth, { CredentialsSignin, type NextAuthConfig } from "next-auth";
import Credentials from "next-auth/providers/credentials";
import GitHub from "next-auth/providers/github";
import Google from "next-auth/providers/google";
import { compare } from "bcryptjs";
import { z } from "zod";
import { DatabaseEnvError } from "@/lib/database-env";
import { getPrisma } from "@/lib/prisma";

const googleClientId = getEnv("GOOGLE_CLIENT_ID", "AUTH_GOOGLE_ID");
const googleClientSecret = getEnv("GOOGLE_CLIENT_SECRET", "AUTH_GOOGLE_SECRET");
const githubClientId = getEnv("GITHUB_CLIENT_ID", "AUTH_GITHUB_ID");
const githubClientSecret = getEnv("GITHUB_CLIENT_SECRET", "AUTH_GITHUB_SECRET");
const authAdapter = getAuthAdapter();

export const enabledOAuthProviders = {
  google: Boolean(googleClientId && googleClientSecret && authAdapter),
  github: Boolean(githubClientId && githubClientSecret && authAdapter),
};

const credentialsSchema = z.object({
  email: z.string().email().transform((value) => value.toLowerCase()),
  password: z.string().min(8),
});

const providers: NextAuthConfig["providers"] = [
  Credentials({
    credentials: {
      email: { label: "Email", type: "email" },
      password: { label: "Password", type: "password" },
    },
    async authorize(credentials) {
      const parsed = credentialsSchema.safeParse(credentials);

      if (!parsed.success) {
        return null;
      }

      let prisma;

      try {
        prisma = getPrisma();
      } catch (error) {
        console.error("Credentials auth database configuration failed:", formatAuthError(error));
        throw new AuthStorageUnavailable();
      }

      if (!prisma) {
        console.error("Credentials auth database client is unavailable.");
        throw new AuthStorageUnavailable();
      }

      let users;

      try {
        users = await withTimeout(
          prisma.$queryRaw<
            Array<{
              id: string;
              email: string;
              name: string | null;
              passwordHash: string | null;
            }>
          >`
            SELECT id, email, name, "passwordHash"
            FROM "User"
            WHERE email = ${parsed.data.email}
            LIMIT 1
          `,
          10_000,
        );
      } catch (error) {
        console.error("Credentials auth lookup failed:", formatAuthError(error));
        throw new AuthStorageUnavailable();
      }

      const user = users[0];

      if (!user?.passwordHash) {
        return null;
      }

      const passwordMatches = await compare(
        parsed.data.password,
        user.passwordHash,
      );

      if (!passwordMatches) {
        return null;
      }

      return {
        id: user.id,
        email: user.email,
        name: user.name,
      };
    },
  }),
];

if (enabledOAuthProviders.google) {
  providers.push(
    Google({
      clientId: googleClientId,
      clientSecret: googleClientSecret,
      allowDangerousEmailAccountLinking: true,
      profile(profile) {
        return {
          id: profile.sub,
          email: profile.email,
          name: profile.name,
          image: profile.picture,
        };
      },
    }),
  );
}

if (enabledOAuthProviders.github) {
  providers.push(
    GitHub({
      clientId: githubClientId,
      clientSecret: githubClientSecret,
      allowDangerousEmailAccountLinking: true,
      userinfo: {
        url: "https://api.github.com/user",
        async request({ tokens }: { tokens: { access_token?: string } }) {
          const headers = {
            Authorization: `Bearer ${tokens.access_token}`,
            "User-Agent": "authjs",
          };
          const profile = await fetch("https://api.github.com/user", {
            headers,
          }).then(async (response) => await response.json() as GitHubProfile);
          const emails = await fetch("https://api.github.com/user/emails", {
            headers,
          }).then(async (response) => {
            if (!response.ok) {
              return [];
            }

            return (await response.json()) as GitHubEmail[];
          });
          const verifiedEmail =
            emails.find((email) => email.primary && email.verified) ??
            emails.find((email) => email.verified && email.email === profile.email) ??
            emails.find((email) => email.verified);

          profile.email = verifiedEmail?.email ?? profile.email ?? null;

          return profile;
        },
      },
      profile(profile) {
        if (!profile.email) {
          console.error(
            "GitHub OAuth profile did not include a verified email address.",
            { id: profile.id, login: profile.login },
          );
          throw new Error("GitHub did not provide a verified email address.");
        }

        return {
          id: String(profile.id ?? profile.login),
          email: profile.email,
          name: profile.name ?? profile.login,
          image: profile.avatar_url,
        };
      },
    }),
  );
}

export const authConfig = {
  adapter: authAdapter,
  secret: getEnv("AUTH_SECRET", "NEXTAUTH_SECRET"),
  pages: {
    signIn: "/signin",
  },
  session: {
    strategy: "jwt",
  },
  providers,
  callbacks: {
    jwt({ token, user }) {
      if (user?.id) {
        token.id = user.id;
      }

      return token;
    },
    session({ session, token }) {
      if (session.user && typeof token.id === "string") {
        session.user.id = token.id;
      }

      return session;
    },
  },
  logger: {
    error(error) {
      console.error("Auth.js error:", error);
    },
    warn(code) {
      console.warn("Auth.js warning:", code);
    },
  },
} satisfies NextAuthConfig;

export const { handlers, auth, signIn, signOut } = NextAuth(authConfig);

function withTimeout<T>(promise: Promise<T>, timeoutMs: number) {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) => {
      setTimeout(() => reject(new Error("Auth database operation timed out.")), timeoutMs);
    }),
  ]);
}

type GitHubProfile = {
  id?: number | string | null;
  email: string | null;
  login?: string | null;
  name?: string | null;
  avatar_url?: string | null;
};

type GitHubEmail = {
  email: string;
  primary: boolean;
  verified: boolean;
};

class AuthStorageUnavailable extends CredentialsSignin {
  code = "auth_storage_unavailable";
}

function getEnv(...names: string[]) {
  for (const name of names) {
    const value = process.env[name]?.trim();

    if (value) {
      return value;
    }
  }

  return undefined;
}

function getAuthAdapter() {
  let prisma;

  try {
    prisma = getPrisma();
  } catch (error) {
    console.error("Auth adapter initialization failed:", formatAuthError(error));
    return undefined;
  }

  if (!prisma) {
    return undefined;
  }

  return PrismaAdapter(
    prisma as unknown as Parameters<typeof PrismaAdapter>[0],
  );
}

function formatAuthError(error: unknown) {
  if (error instanceof DatabaseEnvError) {
    return {
      message: error.message,
      issues: error.issues,
    };
  }

  return error instanceof Error ? error.message : "Unknown error";
}
