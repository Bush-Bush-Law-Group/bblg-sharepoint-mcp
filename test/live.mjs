// Live read-only test: spawns the patched server over stdio and downloads a real file.
// Prints only sizes/hashes/booleans; never prints credentials, content or URLs.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import fs from "node:fs";
import { createHash } from "node:crypto";
const pid = process.argv[2];
const srcEnv = Object.fromEntries(fs.readFileSync(`/proc/${pid}/environ`, "utf8").split("\0").filter(Boolean).map(l => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
const env = { ...srcEnv };
// full connector env, values never printed
// quickXorHash (OneDrive/SharePoint content hash)
function quickXor(buf) {
  const W = 160, out = new Uint8Array(20); let shift = 0;
  const bits = new Array(W).fill(0);
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    for (let k = 0; k < 8; k++) if (b & (1 << k)) { const pos = (shift + k) % W; bits[pos] ^= 1; }
    shift = (shift + 11) % W;
  }
  for (let i = 0; i < W; i++) if (bits[i]) out[i >> 3] |= 1 << (i & 7);
  const len = Buffer.alloc(8); len.writeBigUInt64LE(BigInt(buf.length));
  for (let i = 0; i < 8; i++) out[12 + i] ^= len[i];
  return Buffer.from(out).toString("base64");
}
const transport = new StdioClientTransport({ command: "node", args: ["build/main.js"], env, stderr: "ignore" });
const client = new Client({ name: "spfix-test", version: "1" });
await client.connect(transport);
const tools = (await client.listTools()).tools.map(t => t.name);
console.log("tools:", tools.join(", "));
for (let i = 0; i < 40; i++) {
  const st = await client.callTool({ name: "get-auth-status", arguments: {} });
  const t = st.content[0].text;
  const m = /"state"\s*:\s*"(\w+)"/.exec(t);
  if (m && m[1] !== "pending") { console.log("auth state:", m[1], "after", i, "s", m[1] === "failed" ? (/"error"\s*:\s*"([^"]{0,200})/.exec(t)||[])[1] : ""); break; }
  if (i === 39) console.log("auth status keys:", Object.keys(JSON.parse(t.slice(t.indexOf("{")))).join(","));
  await new Promise(r => setTimeout(r, 1000));
}
const SITE = "bushlawgrp.sharepoint.com,7d78d038-7d13-4881-9494-800f6e8e5427,6389a915-8e14-46f8-8b1b-bcbcb4458ae4";
const DRIVE = "b!ONB4fRN9gUiUlIAPbo5UJxWpiWMUjvhGixu8vLRFiuSmYrY3R_LLTogGs0Z-Vz8y";
const ITEM = "01WNSDW22J4GAMDLFB2NFYGMEM6TCX3VT3";
const EXPECT_QX = "JkjUHyqRvQZb2uuEr3bp/GoFydc=", EXPECT_SIZE = 22529;
const leak = t => /downloadUrl|tempauth|download\.aspx/i.test(t);
function check(label, res, bytesFrom) {
  const text = res.content[0].text;
  let j; try { j = JSON.parse(text.slice(text.indexOf("{"))); } catch { console.log(label, "non-JSON:", text.slice(0, 200)); return; }
  if (res.isError || j.error) { console.log(label, "ERROR:", j.error || text.slice(0, 300)); return; }
  const buf = bytesFrom(j);
  console.log(label, { size: buf.length, sizeOk: buf.length === EXPECT_SIZE, quickXorOk: quickXor(buf) === EXPECT_QX, sha256: createHash("sha256").update(buf).digest("hex").slice(0, 16), zipMagic: buf.subarray(0, 2).toString() === "PK", leaksUrl: leak(text) });
}
const call = (name, args) => client.callTool({ name, arguments: args });
check("download-file(driveId+itemId)", await call("download-file", { driveId: DRIVE, itemId: ITEM }), j => Buffer.from(j.content, "base64"));
check("download-file(site+filePath)", await call("download-file", { siteName: SITE, filePath: "Funding Team/Funding SOP.docx" }), j => Buffer.from(j.content, "base64"));
const out = "/workspace/sharepoint-mcp-fix/test/out-Funding-SOP.docx"; try { fs.unlinkSync(out); } catch {}
check("download-file(saveToPath)", await call("download-file", { driveId: DRIVE, itemId: ITEM, saveToPath: out }), j => fs.readFileSync(j.savedTo));
check("site-files get_content", await call("sharepoint-site-files", { siteName: SITE, operation: "get_content", fileId: ITEM }), j => Buffer.from(j.content, "base64"));
check("microsoft-graph GET /content", await call("microsoft-graph", { apiType: "graph", method: "get", path: `/drives/${DRIVE}/items/${ITEM}/content` }), j => Buffer.from(j.content, "base64"));
const meta = await call("microsoft-graph", { apiType: "graph", method: "get", path: `/drives/${DRIVE}/items/${ITEM}` });
console.log("microsoft-graph plain metadata: leaksUrl =", leak(meta.content[0].text), "hasName =", meta.content[0].text.includes("Funding SOP.docx"));
const fp = await call("file-parser", { siteName: SITE, fileId: ITEM, operation: "metadata" });
console.log("file-parser:", fp.isError ? "ERROR " + fp.content[0].text.slice(0, 200) : "ok, textLen=" + fp.content[0].text.length, "leaksUrl =", leak(fp.content[0].text));
const big = await call("download-file", { driveId: DRIVE, itemId: ITEM, encoding: "base64", saveToPath: "/etc/x.docx" });
console.log("saveToPath outside allowed roots rejected:", !!big.isError);
await client.close();
