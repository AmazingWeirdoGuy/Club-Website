// server/db.ts
import { Pool } from "pg";
import { drizzle } from "drizzle-orm/node-postgres";
import * as schema from "@shared/schema"; // keep if you have this alias; otherwise remove and use drizzle(pool)

const connectionString = process.env.DATABASE_URL;
if (!connectionString) throw new Error("DATABASE_URL is not set");

const pool = new Pool({
  connectionString,
  ssl: { rejectUnauthorized: false }, // Render PG typically needs SSL
});

export const db = drizzle(pool, { schema });

export async function pingDb(): Promise<boolean> {
  const client = await pool.connect();
  try { await client.query("select 1"); return true; }
  finally { client.release(); }
}
