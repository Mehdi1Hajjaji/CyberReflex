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
      async profile(profile) {
        return toOAuthUser({
          email: profile.email,
          name: profile.name,
          image: profile.picture,
        });
      },
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
      async profile(profile) {
        return toOAuthUser({
          email: profile.email,
          name: profile.name ?? profile.login,
          image: profile.avatar_url,
        });
      },
    }),
  ],
  callbacks: {
    signIn({ user, account }) {
      if (!account || account.provider === "credentials") {
        return true;
      }

      return Boolean(user.id && user.email);
    },
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
  login?: string | null;
  name?: string | null;
  avatar_url?: string | null;
};

type GitHubEmail = {
  email: string;
  primary: boolean;
  verified: boolean;
};

async function toOAuthUser(input: {
  email?: string | null;
  name?: string | null;
  image?: string | null;
}) {
  const email = normalizeEmail(input.email);

  if (!email) {
    throw new Error("OAuth provider did not return a usable email address.");
  }

  const storedUser = await findOrCreateOAuthUser({
    email,
    name: input.name,
  });

  if (!storedUser) {
    throw new Error("OAuth user could not be stored.");
  }

  return {
    id: storedUser.id,
    email: storedUser.email,
    name: storedUser.name ?? input.name ?? null,
    image: input.image ?? null,
  };
}

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
