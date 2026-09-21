import test from "node:test";
import assert from "node:assert/strict";
import { fields, parseAuditGroup, parseAuthLine, parseDockerEvent, parseSambaLine } from "./parsers.js";

test("parses quoted audit fields", () => {
  assert.equal(fields('type=PATH name="/srv/samba/a file.txt" key="samba-files"').name, "/srv/samba/a file.txt");
});

test("correlates audit records and decodes proctitle", () => {
  const event = parseAuditGroup([
    'type=SYSCALL msg=audit(1710000000.123:42): arch=c000003e syscall=87 success=yes auid=1000 uid=1000 ses=3 comm="rm" key="samba-files"',
    'type=PATH msg=audit(1710000000.123:42): name="/srv/samba/test.txt"',
    'type=PROCTITLE msg=audit(1710000000.123:42): proctitle=726D002D66002F7372762F73616D62612F746573742E747874',
  ], "pi");
  assert.equal(event?.action, "user-delete");
  assert.equal(event?.path, "/srv/samba/test.txt");
  assert.equal(event?.command, "rm -f /srv/samba/test.txt");
});

test("recognizes ARM64 rename syscalls", () => {
  const event = parseAuditGroup([
    'type=SYSCALL msg=audit(1710000001.000:43): arch=c00000b7 syscall=38 success=yes auid=1000 uid=1000 comm="mv" key="samba-files"',
    'type=PATH msg=audit(1710000001.000:43): name="/srv/samba/new.txt"',
  ], "pi");
  assert.equal(event?.action, "file-move");
});

test("classifies keyed exec records", () => {
  const event = parseAuditGroup([
    'type=SYSCALL msg=audit(1710000002.000:44): arch=c00000b7 syscall=221 success=yes auid=1000 uid=1000 comm="ls" key="user-exec"',
    'type=PROCTITLE msg=audit(1710000002.000:44): proctitle=6C73002D6C61',
  ], "pi");
  assert.equal(event?.action, "user-exec");
});

test("extracts address from PAM audit message", () => {
  const event = parseAuditGroup([
    `type=USER_END msg=audit(1710000003.000:45): pid=1 uid=0 auid=1000 ses=3 msg='op=PAM:session_close acct="joshua" addr=192.0.2.9 terminal=ssh res=success'`,
  ], "pi");
  assert.equal(event?.action, "ssh-session-end");
  assert.equal(event?.remoteAddress, "192.0.2.9");
  assert.equal(event?.actor, "joshua");
});

test("parses SSH failures", () => {
  const event = parseAuthLine("Sep 21 12:00:00 raspberrypi sshd[123]: Failed password for invalid user guest from 192.0.2.2 port 22 ssh2", "pi");
  assert.equal(event?.action, "ssh-login-failed");
  assert.equal(event?.actor, "guest");
});

test("parses Ubuntu ISO-timestamped SSH failures", () => {
  const event = parseAuthLine("2026-09-21T14:31:34.169981+02:00 RaspberryPi5 sshd[123]: Failed password for invalid user probe from 192.0.2.3 port 22 ssh2", "pi");
  assert.equal(event?.action, "ssh-login-failed");
  assert.equal(event?.actor, "probe");
  assert.equal(event?.remoteAddress, "192.0.2.3");
  assert.equal(event?.occurredAt.toISOString(), "2026-09-21T12:31:34.169Z");
});

test("parses docker events", () => {
  const event = parseDockerEvent({ Type: "container", Action: "start", time: 1710000000, Actor: { ID: "abc", Attributes: { name: "web" } } }, "pi");
  assert.equal(event?.process, "web");
});

test("parses containerized Samba full_audit records", () => {
  const event = parseSambaLine("2026-09-21T12:00:00.123Z user=joshua|ip=192.0.2.8|share=files|path=/share|unlink|ok|docs/test.txt", "pi");
  assert.equal(event?.actor, "joshua");
  assert.equal(event?.remoteAddress, "192.0.2.8");
  assert.equal(event?.action, "user-delete");
  assert.equal(event?.path, "docs/test.txt");
});

test("drops Samba metadata noise and recognizes recycle-bin deletes", () => {
  assert.equal(parseSambaLine("2026-09-21T12:00:00.123Z user=joshua|ip=192.0.2.8|share=files|path=/share|stat|ok|docs/test.txt", "pi"), null);
  const deleted = parseSambaLine("2026-09-21T12:00:00.124Z user=joshua|ip=192.0.2.8|share=files|path=/share|renameat|ok|docs/test.txt|/share/.deleted/test.txt", "pi");
  assert.equal(deleted?.action, "user-delete");
});
