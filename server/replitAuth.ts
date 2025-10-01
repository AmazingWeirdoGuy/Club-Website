// === Auth / OIDC bootstrap (portable, no hard REPLIT_DOMAINS requirement) ===

import * as client from "openid-client";
import { Strategy, type VerifyFunction } from "openid-client/passport";

import passport from "passport";
import session from "express-session";
import type { Express, RequestHandler } from "express";
import memoize from "memoizee";
import connectPg from "connect-pg-simple";
import { storage } from "./storage";

// ---- Allowed domains (portable) ----
// Prefer a generic ALLOWED_ORIGINS (comma-separated), fallback to REPLIT_DOMAINS if present.
// If neither is set, we *do not* crash; auth will be considered disabled.
const rawDomains =
  process.env.ALLOWED_ORIGINS ??
  process.env.REPLIT_DOMAINS ??
  "";

const allowedDomains = rawDomains
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

const AUTH_ENABLED = allowedDomains.length > 0 && !!process.env.REPL_ID;

// Helpful warning so you know why login isn’t wired up
if (!AUTH_ENABLED) {
  console.warn(
    "⚠️ Auth disabled: Set ALLOWED_ORIGINS (comma-separated) and REPL_ID to enable OIDC login.\n" +
    "   Example ALLOWED_ORIGINS: https://your-frontend.vercel.app,http://localhost:5173"
  );
}

// ---- OIDC discovery (memoized) ----
const getOidcConfig = memoize(
  async () => {
    return await client.discovery(
      new URL(process.env.ISSUER_URL ?? "https://replit.com/oidc"),
      process.env.REPL_ID!
    );
  },
  { maxAge: 3600 * 1000 }
);

// ---- Session store (Postgres) ----
export function getSession() {
  const sessionTtl = 7 * 24 * 60 * 60 * 1000; // 1 week
  const pgStore = connectPg(session);
  const sessionStore = new pgStore({
    conString: process.env.DATABASE_URL,
    createTableIfMissing: false,
    ttl: sessionTtl,
    tableName: "sessions",
  });
  return session({
    secret: process.env.SESSION_SECRET!,
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: sessionTtl,
    },
  });
}

// ---- helpers ----
function updateUserSession(
  user: any,
  tokens: client.TokenEndpointResponse & client.TokenEndpointResponseHelpers
) {
  user.claims = tokens.claims();
  user.access_token = tokens.access_token;
  user.refresh_token = tokens.refresh_token;
  user.expires_at = user.claims?.exp;
}

async function upsertUser(claims: any) {
  await storage.upsertUser({
    id: claims["sub"],
    email: claims["email"],
    firstName: claims["first_name"],
    lastName: claims["last_name"],
    profileImageUrl: claims["profile_image_url"],
  });
}

// ---- main wiring ----
export async function setupAuth(app: Express) {
  app.set("trust proxy", 1);
  app.use(getSession());
  app.use(passport.initialize());
  app.use(passport.session());

  // If auth is disabled (no domains / REPL_ID), don’t wire OIDC strategies.
  if (!AUTH_ENABLED) {
    // Provide graceful endpoints so routes don’t 404
    app.get("/api/login", (_req, res) =>
      res.status(503).json({ message: "Login is not configured on this deployment." })
    );
    app.get("/api/callback", (_req, res) =>
      res.status(503).json({ message: "Login is not configured on this deployment." })
    );
    app.get("/api/logout", (_req, res) =>
      res.status(200).json({ message: "Already logged out (auth disabled)." })
    );
    return;
  }

  const config = await getOidcConfig();

  const verify: VerifyFunction = async (
    tokens: client.TokenEndpointResponse & client.TokenEndpointResponseHelpers,
    verified: passport.AuthenticateCallback
  ) => {
    const user: any = {};
    updateUserSession(user, tokens);
    await upsertUser(tokens.claims());
    verified(null, user);
  };

  // Register one strategy per allowed domain
  for (const domain of allowedDomains) {
    const strategy = new Strategy(
      {
        name: `replitauth:${domain}`,
        config,
        scope: "openid email profile offline_access",
        callbackURL: `https://${domain}/api/callback`,
      },
      verify
    );
    passport.use(strategy);
  }

  passport.serializeUser((user: Express.User, cb) => cb(null, user));
  passport.deserializeUser((user: Express.User, cb) => cb(null, user));

  app.get("/api/login", (req, res, next) => {
    passport.authenticate(`replitauth:${req.hostname}`, {
      prompt: "login consent",
      scope: ["openid", "email", "profile", "offline_access"],
    })(req, res, next);
  });

  app.get("/api/callback", (req, res, next) => {
    passport.authenticate(`replitauth:${req.hostname}`, {
      successReturnToOrRedirect: "/",
      failureRedirect: "/api/login",
    })(req, res, next);
  });

  app.get("/api/logout", (req, res) => {
    req.logout(() => {
      res.redirect(
        client.buildEndSessionUrl(config, {
          client_id: process.env.REPL_ID!,
          post_logout_redirect_uri: `${req.protocol}://${req.hostname}`,
        }).href
      );
    });
  });
}

// ---- guard for protected routes ----
export const isAuthenticated: RequestHandler = async (req, res, next) => {
  // If auth is disabled, let everything through (or change to 401 if you prefer)
  if (!AUTH_ENABLED) return next();

  const user = req.user as any;

  if (!req.isAuthenticated() || !user.expires_at) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const now = Math.floor(Date.now() / 1000);
  if (now <= user.expires_at) {
    return next();
  }

  const refreshToken = user.refresh_token;
  if (!refreshToken) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const config = await getOidcConfig();
    const tokenResponse = await client.refreshTokenGrant(config, refreshToken);
    updateUserSession(user, tokenResponse);
    return next();
  } catch {
    return res.status(401).json({ message: "Unauthorized" });
  }
};
