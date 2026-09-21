import pg from "pg";
import type { AuditEvent } from "./types.js";
import { config } from "./config.js";

const { Pool } = pg;
export const pool = new Pool({ connectionString: config.databaseUrl, max: 5, idleTimeoutMillis: 30_000 });

export async function migrate(): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS audit_events (
      id BIGSERIAL PRIMARY KEY,
      occurred_at TIMESTAMPTZ NOT NULL,
      received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      host TEXT NOT NULL,
      source TEXT NOT NULL,
      category TEXT NOT NULL,
      action TEXT NOT NULL,
      severity TEXT NOT NULL,
      success BOOLEAN,
      actor TEXT,
      actor_uid INTEGER,
      session_id TEXT,
      remote_address INET,
      path TEXT,
      command TEXT,
      process TEXT,
      message TEXT NOT NULL,
      event_key TEXT NOT NULL UNIQUE,
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb
    );
    CREATE INDEX IF NOT EXISTS audit_events_time_idx ON audit_events (occurred_at DESC);
    CREATE INDEX IF NOT EXISTS audit_events_source_time_idx ON audit_events (source, occurred_at DESC);
    CREATE INDEX IF NOT EXISTS audit_events_actor_time_idx ON audit_events (actor, occurred_at DESC);
    CREATE INDEX IF NOT EXISTS audit_events_action_time_idx ON audit_events (action, occurred_at DESC);
    CREATE INDEX IF NOT EXISTS audit_events_severity_time_idx ON audit_events (severity, occurred_at DESC);
    CREATE INDEX IF NOT EXISTS audit_events_path_idx ON audit_events (path text_pattern_ops) WHERE path IS NOT NULL;
  `);
}

export async function insertEvents(events: AuditEvent[]): Promise<number> {
  if (!events.length) return 0;
  const rows = events.map(event => ({
    occurred_at: event.occurredAt.toISOString(), host: event.host, source: event.source,
    category: event.category, action: event.action, severity: event.severity, success: event.success,
    actor: event.actor, actor_uid: event.actorUid, session_id: event.sessionId,
    remote_address: event.remoteAddress, path: event.path, command: event.command,
    process: event.process, message: event.message, event_key: event.eventKey, metadata: event.metadata,
  }));
  const result = await pool.query({
    text: `INSERT INTO audit_events
      (occurred_at, host, source, category, action, severity, success, actor, actor_uid,
       session_id, remote_address, path, command, process, message, event_key, metadata)
      SELECT x.occurred_at, x.host, x.source, x.category, x.action, x.severity, x.success,
       x.actor, x.actor_uid, x.session_id, nullif(x.remote_address, '')::inet, x.path,
       x.command, x.process, x.message, x.event_key, x.metadata
      FROM jsonb_to_recordset($1::jsonb) AS x(
       occurred_at timestamptz, host text, source text, category text, action text, severity text,
       success boolean, actor text, actor_uid integer, session_id text, remote_address text,
       path text, command text, process text, message text, event_key text, metadata jsonb)
      ON CONFLICT (event_key) DO NOTHING`,
    values: [JSON.stringify(rows)],
  });
  return result.rowCount ?? 0;
}

export async function pruneOldEvents(): Promise<number> {
  if (!config.retentionDays) return 0;
  const result = await pool.query("DELETE FROM audit_events WHERE occurred_at < now() - ($1 * interval '1 day')", [config.retentionDays]);
  return result.rowCount ?? 0;
}
