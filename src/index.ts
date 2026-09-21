import { config, validateConfig } from "./config.js";
import { migrate, pool, pruneOldEvents } from "./db.js";
import { createServer } from "./server.js";
import { Collector } from "./collector.js";

validateConfig();
await migrate();
const deleted = await pruneOldEvents();
if (deleted) console.log(`Retention removed ${deleted} old events`);

const app = createServer();
const server = app.listen(config.port, "0.0.0.0", () => console.log(`Sentinel listening on :${config.port}`));
const collector = config.collectorEnabled ? new Collector() : null;
if (collector) await collector.start();
const pruneTimer = setInterval(() => void pruneOldEvents().catch(console.error), 24 * 60 * 60 * 1000);

async function shutdown(): Promise<void> {
  collector?.stop(); clearInterval(pruneTimer); server.close(); await pool.end(); process.exit(0);
}
process.on("SIGTERM", () => void shutdown());
process.on("SIGINT", () => void shutdown());
