import crypto from "node:crypto";
import express, { type Request, type Response, type NextFunction } from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { config } from "./config.js";
import { pool } from "./db.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../public");
const severityOrder = ["info", "low", "medium", "high", "critical"] as const;

export function severitiesAtOrAbove(level: string): string[] | null {
  const index = severityOrder.indexOf(level as (typeof severityOrder)[number]);
  return index < 0 ? null : severityOrder.slice(index);
}

function safeEqual(actual: string, expected: string): boolean {
  const a = Buffer.from(actual); const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function auth(req: Request, res: Response, next: NextFunction): void {
  if (req.path === "/healthz") return next();
  const [scheme, encoded] = (req.headers.authorization ?? "").split(" ");
  let user = "", password = "";
  if (scheme === "Basic" && encoded) {
    [user, password] = Buffer.from(encoded, "base64").toString("utf8").split(":", 2);
  }
  if (!safeEqual(user, config.dashboardUser) || !safeEqual(password, config.dashboardPassword)) {
    res.set("WWW-Authenticate", 'Basic realm="Sentinel", charset="UTF-8"').status(401).send("Authentication required"); return;
  }
  next();
}

function parseFilters(req: Request): { where: string; values: unknown[] } {
  const clauses = ["occurred_at >= now() - ($1 * interval '1 hour')"];
  const hours = Math.min(Math.max(Number(req.query.hours) || 24, 1), 24 * 365);
  const values: unknown[] = [hours];
  const add = (column: string, value: unknown) => { values.push(value); clauses.push(`${column} = $${values.length}`); };
  if (typeof req.query.source === "string" && req.query.source) add("source", req.query.source);
  if (typeof req.query.severity === "string" && req.query.severity) {
    const levels = severitiesAtOrAbove(req.query.severity);
    if (levels) { values.push(levels); clauses.push(`severity = ANY($${values.length}::text[])`); }
  }
  if (typeof req.query.action === "string" && req.query.action) add("action", req.query.action);
  if (typeof req.query.actor === "string" && req.query.actor) add("actor", req.query.actor);
  if (typeof req.query.success === "string" && ["true", "false"].includes(req.query.success)) add("success", req.query.success === "true");
  if (typeof req.query.q === "string" && req.query.q.trim()) {
    values.push(`%${req.query.q.trim()}%`);
    clauses.push(`(message ILIKE $${values.length} OR path ILIKE $${values.length} OR command ILIKE $${values.length})`);
  }
  return { where: clauses.join(" AND "), values };
}

export function createServer(): express.Express {
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "32kb" }));
  app.get("/healthz", async (_req, res) => {
    try { await pool.query("SELECT 1"); res.json({ status: "ok" }); }
    catch { res.status(503).json({ status: "database-unavailable" }); }
  });
  app.use(auth);
  app.use(express.static(root, { etag: true, maxAge: "1h" }));
  app.get("/sql", (_req, res) => {
    if (!config.sqlConsoleEnabled) return res.status(404).send("SQL console is disabled");
    res.sendFile(path.join(root, "sql.html"));
  });

  app.post("/api/reset", async (req, res, next) => {
    try {
      if (req.body?.confirmation !== "ZURÜCKSETZEN") return res.status(400).json({ error: "Bestätigung stimmt nicht überein." });
      await pool.query("TRUNCATE TABLE audit_events RESTART IDENTITY");
      res.json({ ok: true });
    } catch (error) { next(error); }
  });

  app.post("/api/sql", async (req, res, next) => {
    if (!config.sqlConsoleEnabled) return res.status(404).json({ error: "SQL-Konsole ist deaktiviert." });
    const sql = typeof req.body?.sql === "string" ? req.body.sql.trim() : "";
    if (!sql) return res.status(400).json({ error: "SQL-Befehl fehlt." });
    if (sql.length > 20_000) return res.status(413).json({ error: "SQL-Befehl ist zu lang." });
    const blocked = /\b(?:alter|create|drop)\s+(?:role|user|database|tablespace)\b|\bcopy\b[\s\S]*\bprogram\b|\bpg_(?:read|write|ls_dir|stat_file)\b|\b(?:begin|commit|rollback|savepoint)\b|\bset\s+(?:local\s+)?(?:statement_timeout|lock_timeout)\b/i;
    if (blocked.test(sql)) return res.status(403).json({ error: "Rollen-, Datenbank-, Serverdatei- und Transaktionssteuerung ist in der Web-Konsole gesperrt." });
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SET LOCAL statement_timeout = '15s'; SET LOCAL lock_timeout = '5s'");
      const raw = await client.query(sql) as unknown;
      await client.query("COMMIT");
      const results = (Array.isArray(raw) ? raw : [raw]).map(value => {
        const result = value as { command?: string; rowCount?: number | null; rows?: unknown[]; fields?: Array<{ name: string }> };
        const rows = result.rows ?? [];
        return { command: result.command ?? "", rowCount: result.rowCount ?? null, fields: result.fields?.map(field => field.name) ?? [], rows: rows.slice(0, 500), truncated: rows.length > 500 };
      });
      res.json({ ok: true, results });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      const message = error instanceof Error ? error.message : "SQL-Befehl fehlgeschlagen.";
      res.status(400).json({ error: message });
    } finally { client.release(); }
  });

  app.get("/api/summary", async (req, res, next) => {
    try {
      const { where, values } = parseFilters(req);
      const [stats, sources, actions, actors, storage] = await Promise.all([
        pool.query(`SELECT count(*)::int AS total,
          count(*) FILTER (WHERE severity IN ('high','critical'))::int AS high,
          count(*) FILTER (WHERE success = false)::int AS failed,
          count(DISTINCT actor)::int AS actors,
          max(occurred_at) AS latest FROM audit_events WHERE ${where}`, values),
        pool.query(`SELECT source AS label, count(*)::int AS value FROM audit_events WHERE ${where} GROUP BY source ORDER BY value DESC`, values),
        pool.query(`SELECT action AS label, count(*)::int AS value FROM audit_events WHERE ${where} GROUP BY action ORDER BY value DESC LIMIT 8`, values),
        pool.query(`SELECT coalesce(actor, 'unbekannt') AS label, count(*)::int AS value FROM audit_events WHERE ${where} GROUP BY actor ORDER BY value DESC LIMIT 8`, values),
        pool.query(`SELECT pg_total_relation_size('audit_events')::bigint::text AS total_bytes,
          pg_relation_size('audit_events')::bigint::text AS data_bytes,
          pg_indexes_size('audit_events')::bigint::text AS index_bytes`),
      ]);
      res.json({ stats: stats.rows[0], sources: sources.rows, actions: actions.rows, actors: actors.rows, storage: storage.rows[0] });
    } catch (error) { next(error); }
  });

  app.get("/api/timeline", async (req, res, next) => {
    try {
      const { where, values } = parseFilters(req);
      const hours = Number(values[0]);
      const bucket = hours <= 48 ? "hour" : hours <= 24 * 60 ? "day" : "week";
      const result = await pool.query(`SELECT date_trunc('${bucket}', occurred_at AT TIME ZONE $${values.length + 1}) AS bucket,
        count(*)::int AS total, count(*) FILTER (WHERE severity IN ('high','critical'))::int AS high,
        count(*) FILTER (WHERE success = false)::int AS failed
        FROM audit_events WHERE ${where} GROUP BY bucket ORDER BY bucket`, [...values, config.timezone]);
      res.json({ bucket, points: result.rows });
    } catch (error) { next(error); }
  });

  app.get("/api/events", async (req, res, next) => {
    try {
      const { where, values } = parseFilters(req);
      const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 500);
      values.push(limit);
      const result = await pool.query(`SELECT id, occurred_at, host, source, category, action, severity, success,
        actor, actor_uid, session_id, host(remote_address) AS remote_address, path, command, process, message, metadata
        FROM audit_events WHERE ${where} ORDER BY occurred_at DESC LIMIT $${values.length}`, values);
      res.json({ events: result.rows });
    } catch (error) { next(error); }
  });

  app.get("/api/facets", async (req, res, next) => {
    try {
      const result = await pool.query(`SELECT
        ARRAY(SELECT DISTINCT source FROM audit_events ORDER BY source) AS sources,
        ARRAY(SELECT DISTINCT action FROM audit_events ORDER BY action) AS actions,
        ARRAY(SELECT DISTINCT actor FROM audit_events WHERE actor IS NOT NULL ORDER BY actor LIMIT 200) AS actors`);
      res.json(result.rows[0]);
    } catch (error) { next(error); }
  });

  app.use("/api", (error: unknown, _req: Request, res: Response, _next: NextFunction) => {
    console.error(error); res.status(500).json({ error: "Die Daten konnten nicht geladen werden." });
  });
  app.get("/{*splat}", (_req, res) => res.sendFile(path.join(root, "index.html")));
  return app;
}
