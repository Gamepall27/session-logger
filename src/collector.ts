import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import readline from "node:readline";
import { config } from "./config.js";
import { insertEvents } from "./db.js";
import { parseAuditGroup, parseAuthLine, parseDockerEvent, parseSambaLine } from "./parsers.js";
import type { AuditEvent } from "./types.js";

interface Position { inode: number; offset: number }
type State = Record<string, Position>;

export class Collector {
  private state: State = {};
  private auditGroups = new Map<string, { lines: string[]; touched: number }>();
  private timer?: NodeJS.Timeout;
  private stopped = false;
  private sambaQueue: AuditEvent[] = [];
  private sambaFlushTimer?: NodeJS.Timeout;
  private sambaFlushing = false;
  private stateFile = path.join(config.stateDir, "positions.json");
  private users = new Map<number, string>();

  async start(): Promise<void> {
    fs.mkdirSync(config.stateDir, { recursive: true });
    try { this.state = JSON.parse(fs.readFileSync(this.stateFile, "utf8")); } catch { this.state = {}; }
    try {
      for (const line of fs.readFileSync("/host/etc/passwd", "utf8").split("\n")) {
        const parts = line.split(":"); const uid = Number(parts[2]);
        if (parts[0] && Number.isInteger(uid)) this.users.set(uid, parts[0]);
      }
    } catch { /* Numeric UIDs remain usable if passwd is not mounted. */ }
    await this.poll();
    this.timer = setInterval(() => void this.poll(), 2_000);
    this.collectDocker();
    this.collectSambaDockerLogs();
  }

  stop(): void {
    this.stopped = true;
    if (this.timer) clearInterval(this.timer);
    if (this.sambaFlushTimer) clearTimeout(this.sambaFlushTimer);
  }

  private files(): Array<{ file: string; parser: "audit" | "auth" | "samba" }> {
    const result: Array<{ file: string; parser: "audit" | "auth" | "samba" }> = [
      { file: config.auditLog, parser: "audit" as const },
      { file: config.authLog, parser: "auth" as const },
    ];
    const dir = path.dirname(config.sambaLogGlob);
    const pattern = new RegExp(`^${path.basename(config.sambaLogGlob).replaceAll(".", "\\.").replaceAll("*", ".*")}$`);
    try {
      for (const name of fs.readdirSync(dir)) if (pattern.test(name)) result.push({ file: path.join(dir, name), parser: "samba" });
    } catch { /* Samba logging may not be installed. */ }
    return result;
  }

  private async poll(): Promise<void> {
    const events: AuditEvent[] = [];
    for (const input of this.files()) {
      try {
        const stat = fs.statSync(input.file);
        const old = this.state[input.file];
        let offset = !old ? stat.size : old.inode === stat.ino && old.offset <= stat.size ? old.offset : 0;
        if (!old) this.state[input.file] = { inode: stat.ino, offset }; // First run starts at EOF.
        if (stat.size <= offset) continue;
        const length = stat.size - offset;
        const buffer = Buffer.alloc(length);
        const fd = fs.openSync(input.file, "r");
        fs.readSync(fd, buffer, 0, length, offset);
        fs.closeSync(fd);
        this.state[input.file] = { inode: stat.ino, offset: stat.size };
        const lines = buffer.toString("utf8").split(/\r?\n/).filter(Boolean);
        for (const line of lines) {
          if (input.parser === "audit") this.addAuditLine(line);
          else {
            const event = input.parser === "auth" ? parseAuthLine(line, config.hostName) : parseSambaLine(line, config.hostName);
            if (event) events.push(event);
          }
        }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") console.error(`Collector could not read ${input.file}:`, error);
      }
    }
    events.push(...this.flushAuditGroups(false));
    if (events.length) await insertEvents(events);
    fs.writeFileSync(this.stateFile, JSON.stringify(this.state));
  }

  private addAuditLine(line: string): void {
    const serial = line.match(/msg=audit\(\d+(?:\.\d+)?:(\d+)\)/)?.[1];
    if (!serial) return;
    const group = this.auditGroups.get(serial) ?? { lines: [], touched: Date.now() };
    group.lines.push(line); group.touched = Date.now(); this.auditGroups.set(serial, group);
  }

  private flushAuditGroups(all: boolean): AuditEvent[] {
    const events: AuditEvent[] = [];
    const cutoff = Date.now() - 750;
    for (const [serial, group] of this.auditGroups) {
      if (!all && group.touched > cutoff) continue;
      const event = parseAuditGroup(group.lines, config.hostName);
      if (event) {
        if (event.actorUid != null && this.users.has(event.actorUid) && (!event.actor || event.actor.startsWith("uid:"))) event.actor = this.users.get(event.actorUid)!;
        events.push(event);
      }
      this.auditGroups.delete(serial);
    }
    return events;
  }

  private collectDocker(): void {
    if (this.stopped || !fs.existsSync("/var/run/docker.sock")) return;
    const since = Math.floor(Date.now() / 1000);
    const request = http.request({ socketPath: "/var/run/docker.sock", path: `/events?since=${since}`, method: "GET" }, response => {
      const lines = readline.createInterface({ input: response });
      lines.on("line", line => {
        try {
          const event = parseDockerEvent(JSON.parse(line), config.hostName);
          if (event) void insertEvents([event]).catch(error => console.error("Docker event insert failed:", error));
        } catch { /* Ignore malformed stream records. */ }
      });
      response.on("close", () => { if (!this.stopped) setTimeout(() => this.collectDocker(), 5_000); });
    });
    request.on("error", error => {
      console.error("Docker event stream unavailable:", error.message);
      if (!this.stopped) setTimeout(() => this.collectDocker(), 15_000);
    });
    request.end();
  }

  private collectSambaDockerLogs(): void {
    if (this.stopped || !config.sambaContainer || !fs.existsSync("/var/run/docker.sock")) return;
    const container = encodeURIComponent(config.sambaContainer);
    const request = http.request({
      socketPath: "/var/run/docker.sock",
      path: `/containers/${container}/logs?stdout=1&stderr=1&follow=1&since=${Math.floor(Date.now() / 1000)}&timestamps=1`,
      method: "GET",
    }, response => {
      let framed = Buffer.alloc(0);
      let textBuffer = "";
      const consume = (payload: Buffer) => {
        textBuffer += payload.toString("utf8");
        const lines = textBuffer.split(/\r?\n/); textBuffer = lines.pop() ?? "";
        for (const raw of lines) {
          const event = parseSambaLine(raw, config.hostName);
          if (event) this.enqueueSamba(event);
        }
      };
      response.on("data", (chunk: Buffer) => {
        framed = Buffer.concat([framed, chunk]);
        while (framed.length >= 8) {
          const stream = framed[0]; const length = framed.readUInt32BE(4);
          if ((stream !== 1 && stream !== 2) || length > 16 * 1024 * 1024) { consume(framed); framed = Buffer.alloc(0); break; }
          if (framed.length < 8 + length) break;
          consume(framed.subarray(8, 8 + length)); framed = framed.subarray(8 + length);
        }
      });
      response.on("close", () => { if (!this.stopped) setTimeout(() => this.collectSambaDockerLogs(), 5_000); });
    });
    request.on("error", error => {
      console.error("Samba log stream unavailable:", error.message);
      if (!this.stopped) setTimeout(() => this.collectSambaDockerLogs(), 15_000);
    });
    request.end();
  }

  private enqueueSamba(event: AuditEvent): void {
    this.sambaQueue.push(event);
    if (this.sambaQueue.length > 10_000) {
      const dropped = this.sambaQueue.length - 10_000;
      this.sambaQueue.splice(0, dropped);
      console.error(`Samba queue overflow: dropped ${dropped} oldest events`);
    }
    if (!this.sambaFlushTimer && !this.sambaFlushing) {
      this.sambaFlushTimer = setTimeout(() => {
        this.sambaFlushTimer = undefined;
        void this.flushSamba();
      }, 500);
    }
  }

  private async flushSamba(): Promise<void> {
    if (this.sambaFlushing || !this.sambaQueue.length) return;
    this.sambaFlushing = true;
    const batch = this.sambaQueue.splice(0, 500);
    try {
      await insertEvents(batch);
    } catch (error) {
      console.error("Samba event batch insert failed:", error);
      this.sambaQueue.unshift(...batch);
    } finally {
      this.sambaFlushing = false;
      if (this.sambaQueue.length && !this.stopped) {
        this.sambaFlushTimer = setTimeout(() => {
          this.sambaFlushTimer = undefined;
          void this.flushSamba();
        }, 250);
      }
    }
  }
}
