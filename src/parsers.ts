import crypto from "node:crypto";
import type { AuditEvent, Severity } from "./types.js";

const fieldPattern = /(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)=("(?:\\.|[^"])*"|'[^']*'|[^\s]+)/g;

export function fields(line: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const match of line.matchAll(fieldPattern)) {
    let value = match[2];
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1).replaceAll('\\"', '"');
    }
    out[match[1]] = value;
  }
  return out;
}

function key(input: string): string {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function auditStamp(line: string): { date: Date; serial: string } | null {
  const match = line.match(/msg=audit\((\d+(?:\.\d+)?):(\d+)\)/);
  return match ? { date: new Date(Number(match[1]) * 1000), serial: match[2] } : null;
}

function decodeProctitle(value?: string): string | null {
  if (!value) return null;
  if (!/^[0-9a-f]+$/i.test(value) || value.length % 2) return value;
  try { return Buffer.from(value, "hex").toString("utf8").replaceAll("\0", " ").trim(); }
  catch { return value; }
}

function severity(action: string, success: boolean | null): Severity {
  if (action === "user-delete" || action === "permission-change") return success === false ? "medium" : "high";
  if (action === "ssh-login-failed" || action === "privilege-use") return "medium";
  if (action === "ssh-login" || action === "user-exec") return "low";
  return "info";
}

function actionFor(data: Record<string, string>, all: string): { action: string; category: string } {
  const type = data.type ?? all.match(/^type=([^\s]+)/)?.[1] ?? "AUDIT";
  const syscall = data.SYSCALL ?? data.syscall;
  const arch = (data.arch ?? "").toLowerCase();
  const deleteCalls = arch === "c00000b7" ? ["35"] : ["84", "87", "263"];
  const renameCalls = arch === "c00000b7" ? ["38", "276"] : ["82", "264", "316"];
  const permissionCalls = arch === "c00000b7" ? ["52", "53", "54", "55"] : ["90", "91", "92", "93", "94", "260", "268"];
  const keyName = data.key ?? "";
  if (/USER_LOGIN|USER_AUTH/.test(type)) return { action: data.res === "failed" ? "ssh-login-failed" : "ssh-login", category: "authentication" };
  if (type === "USER_START") return { action: "ssh-session-start", category: "authentication" };
  if (type === "USER_END") return { action: "ssh-session-end", category: "authentication" };
  if (/sudo|su\b/.test(all) || keyName === "privilege") return { action: "privilege-use", category: "privilege" };
  if (/unlink|rmdir/.test(syscall ?? "") || deleteCalls.includes(syscall ?? "") || keyName.includes("delete")) return { action: "user-delete", category: "filesystem" };
  if (/rename/.test(syscall ?? "") || renameCalls.includes(syscall ?? "")) return { action: "file-move", category: "filesystem" };
  if (/chmod|chown|setxattr/.test(syscall ?? "") || permissionCalls.includes(syscall ?? "")) return { action: "permission-change", category: "filesystem" };
  if (keyName.includes("samba") || keyName.includes("filesystem")) return { action: "file-change", category: "filesystem" };
  if (keyName === "user-exec" || type === "EXECVE" || type === "SYSCALL") return { action: "user-exec", category: "process" };
  return { action: "audit-event", category: "audit" };
}

export function parseAuditGroup(lines: string[], host: string): AuditEvent | null {
  const first = lines[0];
  const stamp = auditStamp(first);
  if (!stamp) return null;
  const combined = lines.join(" ");
  const data = Object.assign({}, ...lines.map(line => {
    const record = fields(line);
    if (record.msg?.includes("=")) Object.assign(record, fields(record.msg));
    return record;
  })) as Record<string, string>;
  const auid = Number(data.auid ?? data.uid ?? -1);
  if (auid === 4294967295 || auid < 0) return null;
  const { action, category } = actionFor(data, combined);
  const command = decodeProctitle(data.proctitle) ?? data.exe ?? data.comm ?? null;
  const path = data.name ?? null;
  const success = data.success ? data.success === "yes" : data.res ? data.res !== "failed" : null;
  const actor = data.acct ?? (Number.isFinite(auid) ? `uid:${auid}` : null);
  return {
    occurredAt: stamp.date, host, source: "audit", category, action,
    severity: severity(action, success), success, actor, actorUid: auid,
    sessionId: data.ses ?? null, remoteAddress: data.addr && data.addr !== "?" ? data.addr : null,
    path, command, process: data.comm ?? null,
    message: [actor, action.replaceAll("-", " "), path ?? command].filter(Boolean).join(" · "),
    eventKey: `audit:${host}:${stamp.serial}`,
    metadata: { serial: stamp.serial, key: data.key, terminal: data.terminal, pid: data.pid, ppid: data.ppid, records: lines },
  };
}

export function parseAuthLine(line: string, host: string): AuditEvent | null {
  const match = line.match(/sshd.*(?:Accepted (\S+)|Failed \S+).* for (?:invalid user )?(\S+) from ([0-9a-f:.]+)/i);
  if (!match) return null;
  const now = new Date();
  const isoTimestamp = line.match(/^(\d{4}-\d\d-\d\dT\S+)/)?.[1];
  const legacyTimestamp = line.match(/^(\S+\s+\d+\s+\d\d:\d\d:\d\d)/)?.[1];
  const occurredAt = isoTimestamp ? new Date(isoTimestamp) : new Date(`${legacyTimestamp} ${now.getFullYear()}`);
  const ok = Boolean(match[1]);
  const action = ok ? "ssh-login" : "ssh-login-failed";
  return {
    occurredAt, host, source: "ssh", category: "authentication", action,
    severity: severity(action, ok), success: ok, actor: match[2], actorUid: null,
    sessionId: null, remoteAddress: match[3], path: null, command: null, process: "sshd",
    message: `${ok ? "SSH-Anmeldung" : "Fehlgeschlagene SSH-Anmeldung"} · ${match[2]} · ${match[3]}`,
    eventKey: `auth:${host}:${key(line)}`, metadata: { method: match[1] ?? "unknown", raw: line },
  };
}

export function parseSambaLine(line: string, host: string): AuditEvent | null {
  const auditParts = line.match(/(?:smbd_audit:\s*)?(user=[^|]*\|ip=[^|]*\|share=[^|]*\|path=[^|]*)\|([a-z0-9_]+)\|([^|]+)\|(.*)$/i);
  if (!auditParts && !/\b(connect|disconnect|rename|unlink|mkdir|rmdir|open|close|read|pread|write|pwrite|chmod|chown)\b/i.test(line)) return null;
  const actionWord = (auditParts?.[2] ?? line.match(/\b(connect|disconnect|rename|unlink|mkdir|rmdir|open|close|read|pread|write|pwrite|chmod|chown)\b/i)?.[1] ?? "activity").toLowerCase();
  const userOperations = new Set(["connect", "disconnect", "mkdir", "rmdir", "open", "close", "read", "pread", "write", "pwrite", "create_file", "rename", "renameat", "unlink", "unlinkat", "chmod", "fchmod", "chown", "fchown"]);
  if (auditParts && !userOperations.has(actionWord)) return null;
  let action = ["unlink", "unlinkat", "rmdir"].includes(actionWord) ? "user-delete"
    : ["rename", "renameat"].includes(actionWord) ? "file-move"
    : ["chmod", "chown", "fchmod", "fchown"].includes(actionWord) ? "permission-change"
    : ["open", "close", "read", "pread", "sendfile", "opendir", "readdir", "stat", "lstat"].includes(actionWord) ? "file-read"
    : ["connect", "disconnect"].includes(actionWord) ? "samba-session"
    : ["write", "pwrite", "mkdir", "ftruncate", "truncate"].includes(actionWord) ? "file-change"
    : actionWord === "create_file" ? "file-read"
    : `samba-${actionWord}`;
  const user = line.match(/(?:user|uid|account)[=: ]+([\w.@-]+)/i)?.[1] ?? null;
  const remote = line.match(/\b(?:ip|client)[=: ]+([0-9a-f:.]+)/i)?.[1] ?? null;
  let filePath = (auditParts?.[4] ?? line.match(/\bpath=([^|]+)/i)?.[1] ?? line.match(/(?:file|name)[=: ]+"?([^",]+)"?/i)?.[1])?.trim() ?? null;
  if (actionWord === "create_file" && filePath?.includes("|")) filePath = filePath.split("|").at(-1) ?? filePath;
  if (["rename", "renameat"].includes(actionWord) && filePath?.includes("/.deleted/")) action = "user-delete";
  const auditSuccess = auditParts ? /^(ok|success)$/i.test(auditParts[3].trim()) : true;
  return {
    occurredAt: /^\d{4}-\d\d-\d\dT\S+/.test(line) ? new Date(line.split(" ", 1)[0]) : new Date(), host, source: "samba", category: "filesystem", action,
    severity: severity(action, auditSuccess), success: auditSuccess, actor: user, actorUid: null,
    sessionId: null, remoteAddress: remote, path: filePath, command: null, process: "smbd",
    message: ["Samba", user, actionWord, filePath].filter(Boolean).join(" · "),
    eventKey: `samba:${host}:${key(line)}`, metadata: { operation: actionWord, raw: line },
  };
}

export function parseDockerEvent(event: Record<string, unknown>, host: string): AuditEvent | null {
  const type = String(event.Type ?? event.type ?? "container");
  const action = String(event.Action ?? event.action ?? "activity");
  const time = Number(event.timeNano ?? 0) / 1e6 || Number(event.time ?? Date.now() / 1000) * 1000;
  const actor = (event.Actor as { Attributes?: Record<string, string> } | undefined)?.Attributes ?? {};
  const id = String((event.Actor as { ID?: string } | undefined)?.ID ?? "");
  if (!id) return null;
  if (actor.name?.startsWith("session-logger-") && action.startsWith("exec_")) return null;
  return {
    occurredAt: new Date(time), host, source: "docker", category: "container", action: `docker-${action}`,
    severity: /die|kill|destroy|remove/.test(action) ? "medium" : "info", success: true,
    actor: null, actorUid: null, sessionId: null, remoteAddress: null, path: null,
    command: null, process: actor.name ?? id.slice(0, 12), message: `Docker ${type} · ${actor.name ?? id.slice(0, 12)} · ${action}`,
    eventKey: `docker:${host}:${id}:${action}:${Math.floor(time)}`, metadata: event,
  };
}
