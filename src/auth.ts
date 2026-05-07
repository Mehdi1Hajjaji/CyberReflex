import NextAuth, { type NextAuthConfig } from "next-auth";
import Credentials from "next-auth/providers/credentials";
import GitHub from "next-auth/providers/github";
import Google from "next-auth/providers/google";
import { compare } from "bcryptjs";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { getPrisma } from "@/lib/prisma";

const credentialsSchema = z.object({
  email: z.string().email().transform((value) => value.toLowerCase()),
  password: z.string().min(8),
});

export const authConfig = {
  pages: {
    signIn: "/signin",
  },
  session: {
    strategy: "jwt",
  },
  providers: [
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

        const prisma = getPrisma();
        if (!prisma) {
          return null;
        }

        const users = await withTimeout(
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
        ).catch(() => []);
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
    Google({
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    }),
    GitHub({
      clientId: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
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

          profile.email = verifiedEmail?.email ?? null;

          return profile;
        },
      },
    }),
  ],
  callbacks: {
    async signIn({ user, account, profile }) {
      if (!account || account.provider === "credentials") {
        return true;
      }

      const email = normalizeEmail(user.email ?? getProfileEmail(profile));

      if (!email) {
        return false;
      }

      if (account.provider === "google" && !isGoogleEmailVerified(profile)) {
        return false;
      }

      const storedUser = await findOrCreateOAuthUser({
        email,
        name: user.name ?? getProfileName(profile),
      });

      if (!storedUser) {
        return false;
      }

      user.id = storedUser.id;
      user.email = storedUser.email;
      user.name = storedUser.name ?? user.name;

      return true;
    },
    async jwt({ token, user, account, profile }) {
      if (account && account.provider !== "credentials") {
        const email = normalizeEmail(user?.email ?? token.email ?? getProfileEmail(profile));
        const storedUser = email
          ? await findOrCreateOAuthUser({
              email,
              name: user?.name ?? token.name ?? getProfileName(profile),
            })
          : null;

        if (!storedUser) {
          return null;
        }

        token.id = storedUser.id;
        token.email = storedUser.email;
        token.name = storedUser.name ?? token.name;
      } else if (user?.id) {
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

type StoredAuthUser = {
  id: string;
  email: string;
  name: string | null;
};

type GitHubProfile = {
  email: string | null;
};

type GitHubEmail = {
  email: string;
  primary: boolean;
  verified: boolean;
};

async function findOrCreateOAuthUser(input: {
  email: string;
  name?: string | null;
}) {
  const email = normalizeEmail(input.email);

  if (!email) {
    return null;
  }

  const prisma = getPrisma();
  if (!prisma) {
    return null;
  }

  const name = input.name?.trim() || null;

  const users = await withTimeout(
    prisma.$queryRaw<StoredAuthUser[]>`
      INSERT INTO "User" (id, email, name, "passwordHash", plan, "createdAt")
      VALUES (${randomUUID()}, ${email}, ${name}, NULL, 'free', NOW())
      ON CONFLICT (email) DO UPDATE
      SET name = COALESCE("User".name, EXCLUDED.name)
      RETURNING id, email, name
    `,
    10_000,
  ).catch(() => []);

  return users[0] ?? null;
}

function normalizeEmail(email: unknown) {
  return typeof email === "string" && email.trim()
    ? email.trim().toLowerCase()
    : null;
}

function getProfileEmail(profile: unknown) {
  return typeof profile === "object" && profile && "email" in profile
    ? profile.email
    : null;
}

function getProfileName(profile: unknown) {
  if (!profile || typeof profile !== "object" || !("name" in profile)) {
    return null;
  }

  return typeof profile.name === "string" ? profile.name : null;
}

function isGoogleEmailVerified(profile: unknown) {
  if (!profile || typeof profile !== "object" || !("email_verified" in profile)) {
    return false;
  }

  return profile.email_verified === true;
}
