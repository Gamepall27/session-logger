export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface AuditEvent {
  occurredAt: Date;
  receivedAt?: Date;
  host: string;
  source: "audit" | "ssh" | "samba" | "docker" | "system";
  category: string;
  action: string;
  severity: Severity;
  success: boolean | null;
  actor: string | null;
  actorUid: number | null;
  sessionId: string | null;
  remoteAddress: string | null;
  path: string | null;
  command: string | null;
  process: string | null;
  message: string;
  eventKey: string;
  metadata: Record<string, unknown>;
}
