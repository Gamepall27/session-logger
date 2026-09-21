import path from "node:path";

function int(name: string, fallback: number): number {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(value) || value < 0) throw new Error(`${name} must be a non-negative integer`);
  return value;
}

function bool(name: string, fallback: boolean): boolean {
  const value = process.env[name];
  return value == null ? fallback : value.toLowerCase() === "true";
}

export const config = {
  databaseUrl: process.env.DATABASE_URL ?? "",
  dashboardUser: process.env.DASHBOARD_USER ?? "admin",
  dashboardPassword: process.env.DASHBOARD_PASSWORD ?? "",
  port: int("PORT", 8080),
  hostName: process.env.HOST_NAME ?? "raspberrypi5",
  timezone: process.env.TIMEZONE ?? "Europe/Berlin",
  retentionDays: int("RETENTION_DAYS", 365),
  collectorEnabled: bool("COLLECTOR_ENABLED", true),
  sqlConsoleEnabled: bool("SQL_CONSOLE_ENABLED", false),
  auditLog: process.env.AUDIT_LOG ?? "/host/var/log/audit/audit.log",
  authLog: process.env.AUTH_LOG ?? "/host/var/log/auth.log",
  sambaLogGlob: process.env.SAMBA_LOG_GLOB ?? "/host/var/log/samba/log.*",
  sambaContainer: process.env.SAMBA_CONTAINER ?? "samba",
  stateDir: path.resolve(process.env.STATE_DIR ?? "/data"),
};

export function validateConfig(): void {
  const missing = [
    !config.databaseUrl && "DATABASE_URL",
    !config.dashboardPassword && "DASHBOARD_PASSWORD",
  ].filter(Boolean);
  if (missing.length) throw new Error(`Missing required environment variables: ${missing.join(", ")}`);
  if (config.dashboardPassword.length < 12) throw new Error("DASHBOARD_PASSWORD must contain at least 12 characters");
}
