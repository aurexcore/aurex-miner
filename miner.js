#!/usr/bin/env node
"use strict";

const os = require("os");
const crypto = require("crypto");
const { Worker, isMainThread, parentPort, workerData } = require("worker_threads");

if (isMainThread) {
  require("dotenv").config({ quiet: true });
}

const {
  APIClient,
  FetchProvider,
  ABIEncoder,
  Name,
  UInt64,
  Checksum256,
  TimePointSec,
  PrivateKey,
  Transaction,
  SignedTransaction,
  PackedTransaction,
  CompressionType,
} = require("@wharfkit/antelope");

if (!isMainThread) {
  const { workerId, diffBits, powHeaderHex, startNonceStr, stepStr, batch, reportEvery } = workerData;

  const diff = Number(diffBits) >>> 0;
  const header = Buffer.from(powHeaderHex, "hex"); // 40 bytes
  const buf = Buffer.allocUnsafe(48); // header(40) + nonce(8)
  header.copy(buf, 0);

  const nonceOffset = 40;
  let nonce = BigInt(startNonceStr);
  const step = BigInt(stepStr);

  function sha256(b) {
    return crypto.createHash("sha256").update(b).digest();
  }

  function leadingZeroBits(buf32) {
    let count = 0;
    for (let i = 0; i < 32; i++) {
      const v = buf32[i];
      if (v === 0) {
        count += 8;
        continue;
      }
      for (let bit = 7; bit >= 0; bit--) {
        if ((v >> bit) & 1) return count;
        count++;
      }
      return count;
    }
    return count;
  }

  let hashes = 0;
  let bestLz = 0;
  let lastHashHex = "";
  let lastNonceStr = "";
  let stopped = false;

  parentPort.on("message", (m) => {
    if (m?.type === "stop") stopped = true;
  });

  function workLoop() {
    const t0 = Date.now();

    for (let i = 0; i < batch && !stopped; i++) {
      buf.writeBigUInt64LE(BigInt.asUintN(64, nonce), nonceOffset);

      const h = sha256(buf);
      const lz = leadingZeroBits(h);

      hashes++;
      if (lz > bestLz) bestLz = lz;

      if ((hashes & 4095) === 0) {
        lastHashHex = h.toString("hex");
        lastNonceStr = nonce.toString();
      }

      if (lz >= diff) {
        parentPort.postMessage({
          type: "found",
          workerId,
          nonce: nonce.toString(),
          lz,
          hashHex: h.toString("hex"),
        });
        stopped = true;
        break;
      }

      nonce += step;
    }

    const dt = Date.now() - t0;
    if ((hashes % reportEvery) === 0 || dt > 250) {
      parentPort.postMessage({
        type: "report",
        workerId,
        hashes,
        bestLz,
        lastHashHex,
        lastNonceStr,
      });
    }

    if (!stopped) setImmediate(workLoop);
  }

  parentPort.postMessage({ type: "ready", workerId });
  workLoop();
  return;
}

function arg(name, def = null) {
  const i = process.argv.indexOf(name);
  if (i === -1) return def;
  const v = process.argv[i + 1];
  if (!v || v.startsWith("--")) return def;
  return v;
}

function toInt(v, def) {
  if (v === undefined || v === null || v === "") return def;
  const n = Number(v);
  return Number.isFinite(n) ? Math.max(0, Math.floor(n)) : def;
}

function toBool(v, def = false) {
  if (v === undefined || v === null || v === "") return def;
  const s = String(v).trim().toLowerCase();
  if (["1", "true", "yes", "y", "on"].includes(s)) return true;
  if (["0", "false", "no", "n", "off"].includes(s)) return false;
  return def;
}

function clampInt(n, lo, hi) {
  const x = Number.isFinite(n) ? Math.floor(n) : lo;
  return Math.max(lo, Math.min(hi, x));
}

function cpuCount() {
  const ap = typeof os.availableParallelism === "function" ? os.availableParallelism() : 0;
  const c = ap > 0 ? ap : os.cpus()?.length || 4;
  return Math.max(1, c);
}

function parseThreads(vRaw) {
  const v = (vRaw ?? "").toString().trim().toLowerCase();
  const c = cpuCount();
  if (!v || v === "auto" || v === "a" || v === "0") return clampInt(c > 1 ? c - 1 : 1, 1, 256);
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return clampInt(c > 1 ? c - 1 : 1, 1, 256);
  return clampInt(n, 1, 256);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const nowMs = () => Date.now();

const ANSI = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  gray: "\x1b[90m",
  hideCursor: "\x1b[?25l",
  showCursor: "\x1b[?25h",
  clearLine: "\x1b[2K",
  goto: (row, col = 1) => `\x1b[${row};${col}H`,
};

const c = (color, s) => `${ANSI[color] || ""}${s}${ANSI.reset}`;

function safeCols() {
  return Math.max(72, Math.min(process.stdout.columns || 100, 140));
}

function hrLine(width) {
  return c("gray", "─".repeat(width));
}

function shortHex(hex, n = 24) {
  const s = String(hex || "");
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

function formatHps(hps) {
  if (!Number.isFinite(hps) || hps <= 0) return "0 H/s";
  const units = ["H/s", "kH/s", "MH/s", "GH/s", "TH/s"];
  let v = hps;
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v.toFixed(v >= 100 ? 0 : v >= 10 ? 1 : 2)} ${units[i]}`;
}

function formatBytes(n) {
  if (!Number.isFinite(n) || n <= 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

function cpuSpecSnapshot() {
  const cpus = os.cpus?.() || [];
  const model = (cpus[0]?.model || "CPU").trim();
  const mhz = Number(cpus[0]?.speed || 0);
  const threads = Math.max(1, cpus.length || cpuCount());
  const coresGuess = Math.max(1, Math.round(threads / 2)); // safe guess for i7-860 like (4C/8T)
  const mem = os.totalmem?.() || 0;
  const host = (os.hostname?.() || "host").trim();
  const plat = `${os.platform?.() || "linux"} ${os.release?.() || ""}`.trim();
  return {
    host,
    platform: plat,
    cpuModel: model,
    cpuMhz: mhz,
    threads,
    coresGuess,
    memTotal: mem,
  };
}

function createRenderer({ enabled }) {
  const isTTY = !!process.stdout.isTTY && enabled;
  const maxW = () => safeCols();

  let inited = false;
  let lastLines = [];
  let lineCount = 0;

  function padToWidth(s) {
    const w = maxW();
    const t = String(s ?? "");
    return t.length >= w ? t.slice(0, w) : t + " ".repeat(w - t.length);
  }

  function init(lines) {
    if (!isTTY) return;
    inited = true;
    lastLines = lines.map((x) => padToWidth(x));
    lineCount = lastLines.length;

    process.stdout.write(ANSI.hideCursor);
    process.stdout.write(ANSI.goto(1, 1));
    for (let i = 0; i < lastLines.length; i++) {
      process.stdout.write(ANSI.clearLine + lastLines[i] + (i === lastLines.length - 1 ? "" : "\n"));
    }
  }

  function render(lines) {
    if (!isTTY) return;

    const next = lines.map((x) => padToWidth(x));

    if (!inited) {
      init(next);
      return;
    }

    const n = Math.max(lineCount, next.length);

    for (let i = 0; i < n; i++) {
      const a = lastLines[i] ?? "";
      const b = next[i] ?? "";
      if (a === b) continue;

      process.stdout.write(ANSI.goto(i + 1, 1));
      process.stdout.write(ANSI.clearLine + b);
    }

    if (next.length < lineCount) {
      for (let i = next.length; i < lineCount; i++) {
        process.stdout.write(ANSI.goto(i + 1, 1));
        process.stdout.write(ANSI.clearLine);
      }
    }

    lastLines = next;
    lineCount = next.length;
  }

  function close() {
    if (!isTTY) return;
    try {
      process.stdout.write(ANSI.showCursor);
      process.stdout.write("\n");
    } catch { }
  }

  return { isTTY, render, close };
}

function errToOneLine(e) {
  const msg = e?.message ? String(e.message) : String(e);
  const status = e?.status ? `HTTP ${e.status}` : "";
  const code = e?.code ? String(e.code) : "";
  const extra = [status, code].filter(Boolean).join(" ");
  return extra ? `${msg} (${extra})` : msg;
}

function isRetryable(e) {
  const msg = String(e?.message || e || "").toLowerCase();
  const code = String(e?.code || "").toLowerCase();
  const status = Number(e?.status || 0);

  if (status === 429) return true;
  if (status >= 500 && status <= 599) return true;
  if (msg.includes("fetch failed")) return true;
  if (msg.includes("timeout") || msg.includes("timed out")) return true;
  if (msg.includes("overloaded") || msg.includes("temporarily")) return true;
  if (msg.includes("too many") || msg.includes("rate")) return true;
  if (code.includes("econnreset") || code.includes("econnrefused") || code.includes("etimedout")) return true;
  if (code.includes("enotfound") || code.includes("eai_again")) return true;
  return false;
}

function isTaposOrExpired(err) {
  const m = String(err?.message || err || "").toLowerCase();
  return (
    m.includes("expired") ||
    m.includes("tapos") ||
    m.includes("irrelevant") ||
    m.includes("unknown block") ||
    m.includes("invalid ref block") ||
    m.includes("trx is too old") ||
    m.includes("transaction has expired")
  );
}

async function withRetryQuiet(fn, opts = {}) {
  const { tries = 5, baseDelay = 250, maxDelay = 4000, label = "", onRetry = null } = opts;

  let last;
  for (let i = 0; i < tries; i++) {
    try {
      return await fn();
    } catch (e) {
      last = e;
      if (!isRetryable(e) || i === tries - 1) break;

      const jitter = Math.floor(Math.random() * 200);
      const delay = Math.min(maxDelay, baseDelay * 2 ** i) + jitter;

      if (typeof onRetry === "function") onRetry(i + 1, delay, e, label);
      await sleep(delay);
    }
  }
  throw last;
}

async function fetchJsonWithTimeout(url, body, timeoutMs) {
  const f = globalThis.fetch;
  if (typeof f !== "function") throw new Error("Global fetch() not available. Use Node 18+.");

  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);

  try {
    const res = await f(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });

    const text = await res.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      const err = new Error(`RPC non-JSON response`);
      err.status = res.status;
      err.responseText = text?.slice?.(0, 5000);
      throw err;
    }

    if (!res.ok) {
      const err = new Error(`RPC HTTP ${res.status}`);
      err.status = res.status;
      err.json = json;
      throw err;
    }

    return json;
  } catch (e) {
    if (e?.name === "AbortError") {
      const err = new Error(`RPC timeout after ${timeoutMs}ms`);
      err.code = "ETIMEDOUT";
      throw err;
    }
    throw e;
  } finally {
    clearTimeout(t);
  }
}

function refBlockPrefixFromBlockId(blockIdHex) {
  const b = Buffer.from(String(blockIdHex), "hex");
  return b.readUInt32LE(8);
}

function encodeMineActionData(minerName, nonceU64String) {
  const enc = new ABIEncoder();
  Name.from(minerName).toABI(enc);
  UInt64.from(nonceU64String).toABI(enc);
  return enc.getData();
}

async function getCurrencyBalanceStringDirect(endpoint, code, account, symbol, timeoutMs) {
  const base = String(endpoint || "").replace(/\/+$/, "");
  const url = base + "/v1/chain/get_currency_balance";
  const rows = await fetchJsonWithTimeout(url, { code, account, symbol }, timeoutMs);
  if (!Array.isArray(rows) || rows.length === 0) return `0 ${symbol}`;
  return String(rows[0]);
}

function createRollingLog(maxLines) {
  const buf = [];
  const max = Math.max(2, Number(maxLines || 8));

  function push(line) {
    const s = String(line ?? "");
    if (!s) return;
    buf.push(s);
    while (buf.length > max) buf.shift();
  }

  function setLast(line) {
    const s = String(line ?? "");
    if (!s) return push(s);
    if (buf.length === 0) return push(s);
    buf[buf.length - 1] = s;
  }

  function clear() {
    buf.length = 0;
  }

  function lines() {
    return buf.slice();
  }

  return { push, setLast, clear, lines };
}

function buildDashboardLines(state) {
  const {
    endpoint,
    contract,
    miner,
    perm,
    mode,
    threads,
    pcSpec,
    heightStr,
    diffBits,
    challengeHex,
    bestLz,
    lastHashHex,
    lastNonceStr,
    foundCount,
    pushedCount,
    failedCount,
    totalHps,
    uptimeSec,
    footerLine,
    auxBalanceStr,
    auxSymbol,
    footerLogLines,
  } = state;

  const w = safeCols();
  const up = Number.isFinite(uptimeSec) ? uptimeSec : 0;

  const top =
    `${c("bold", "Aurex PoW Miner")} ${c("gray", "·")} ${c("magenta", contract)}  ` +
    `${c("gray", "·")} ${c("cyan", formatHps(totalHps))}  ${c("gray", "·")} ${c("yellow", `${threads}T`)}  ` +
    `${c("gray", "·")} ${c("gray", `up ${up}s`)}`;

  const pc1 = `${c("gray", "Host")}     ${pcSpec?.host || "—"}   ${c("gray", "OS")} ${pcSpec?.platform || "—"}`;
  const cpuHz = pcSpec?.cpuMhz ? `${pcSpec.cpuMhz} MHz` : "";
  const cpuCT = pcSpec?.threads ? `${pcSpec.coresGuess || "?"}C/${pcSpec.threads}T` : "";
  const pc2 =
    `${c("gray", "CPU")}      ${pcSpec?.cpuModel || "—"}  ` +
    `${c("gray", "·")} ${c("gray", cpuCT || "—")}  ` +
    `${c("gray", "·")} ${c("gray", cpuHz || "—")}`;
  const pc3 = `${c("gray", "RAM")}      ${pcSpec?.memTotal ? formatBytes(pcSpec.memTotal) : "—"}`;

  const l1 = `${c("gray", "Endpoint")}  ${endpoint}`;
  const l2 = `${c("gray", "Miner")}     ${miner}@${perm}   ${c("gray", "Mode")} ${mode}`;
  const l3 =
    `${c("gray", "Height")}    ${c("bold", heightStr)}   ` +
    `${c("gray", "Diff")} ${c("bold", String(diffBits))}   ` +
    `${c("gray", "Best")} ${c("bold", String(bestLz))}`;

  const l4 = `${c("gray", "Challenge")} ${c("cyan", challengeHex)}`;
  const l5 =
    `${c("gray", "Last hash")} ${lastHashHex ? c("gray", shortHex(lastHashHex, 64)) : c("gray", "—")}   ` +
    `${c("gray", "nonce")} ${lastNonceStr ? c("gray", lastNonceStr) : c("gray", "—")}`;

  const l6 =
    `${c("gray", "Stats")}     found=${c("green", String(foundCount))}  ` +
    `pushed=${c("cyan", String(pushedCount))}  failed=${c("red", String(failedCount))}`;

  const bal = `${c("gray", "AUX")}       ${auxBalanceStr ? c("bold", auxBalanceStr) : c("gray", `0 ${auxSymbol}`)}`;

  const footer = footerLine ? c("yellow", footerLine) : c("gray", "Mining…");

  const lines = [
    top,
    hrLine(w),
    pc1,
    pc2,
    pc3,
    hrLine(w),
    l1,
    l2,
    l3,
    l4,
    l5,
    l6,
    bal,
    hrLine(w),
    footer,
  ];

  if (footerLogLines && footerLogLines.length) {
    lines.push("");
    for (const ln of footerLogLines) lines.push(ln);
  }

  return lines;
}

async function main() {
  const minerRaw = arg("--miner") || process.env.MINER;
  const permRaw = arg("--perm") || process.env.PERM || "active";
  const threadsRaw = arg("--threads") || process.env.THREADS;

  if (!minerRaw) {
    console.error(c("red", "Missing MINER in .env or use --miner <account>"));
    process.exit(1);
  }

  const miner = String(minerRaw).trim().split("@")[0].trim();
  const perm = String(permRaw).trim();

  Name.from(miner);
  Name.from(perm);

  const ENDPOINT = process.env.ENDPOINT || "https://api.windcrypto.com";
  const CONTRACT = process.env.CONTRACT || "mine.aurex";

  const SCOPE = CONTRACT;
  const TABLE = "global";
  const GLOBAL_ID = UInt64.from(1);

  const AUX_SYMBOL = (process.env.AUX_SYMBOL || "AUX").trim();
  const TOKEN_CONTRACT_FALLBACK = String(process.env.TOKEN_CONTRACT || "token.aurex").trim();

  const READ_RETRY = Math.max(1, toInt(process.env.READ_RETRY, 5));
  const PUSH_RETRY = Math.max(1, toInt(process.env.PUSH_RETRY, 3));
  const READ_TIMEOUT_MS = Math.max(2500, toInt(process.env.READ_TIMEOUT_MS, 12000));

  const GLOBAL_REFRESH_EVERY_SEC_BASE = Math.max(5, toInt(process.env.GLOBAL_REFRESH_EVERY_SEC, 30));

  const UI_TICK_MS = Math.max(60, toInt(process.env.UI_TICK_MS, 120));
  const HPS_REFRESH_MS = Math.max(250, toInt(process.env.HPS_REFRESH_MS, 500));

  const RANDOM_START = toBool(process.env.RANDOM_START, false);
  const START_NONCE = process.env.START_NONCE ?? "0";

  const EXPIRE_SEC = Math.max(10, toInt(process.env.EXPIRE_SEC, 60));
  const COMPRESSION = String(process.env.COMPRESSION ?? "0") === "1" ? CompressionType.zlib : CompressionType.none;

  const THREADS = parseThreads(threadsRaw);
  const WORKER_BATCH = Math.max(256, toInt(process.env.WORKER_BATCH, 50_000));
  const WORKER_REPORT_EVERY = Math.max(1024, toInt(process.env.WORKER_REPORT_EVERY, 200_000));

  const pkStr = (process.env.PRIVATE_KEY || "").trim();
  const privateKey = pkStr ? PrivateKey.fromString(pkStr) : null;

  const BROADCAST_ON = (process.env.BROADCAST ?? "1") !== "0";

  const client = new APIClient({ provider: new FetchProvider(ENDPOINT) });

  let stop = false;
  process.on("SIGINT", () => (stop = true));
  process.on("SIGTERM", () => (stop = true));

  const renderer = createRenderer({ enabled: true });
  const isTTY = renderer.isTTY;

  const pcSpec = cpuSpecSnapshot();

  const minerValueLE = Buffer.from(Name.from(miner).value.byteArray);
  if (minerValueLE.length !== 8) throw new Error("Unexpected Name byteArray length");

  const startTime = nowMs();

  let diffBits = 0;
  let heightStr = "0";
  let tokenContract = TOKEN_CONTRACT_FALLBACK;
  let challengeHex = "";

  let bestLz = 0;
  let lastHashHex = "";
  let lastNonceStr = "";

  let foundCount = 0;
  let pushedCount = 0;
  let failedCount = 0;

  let auxBalanceStr = `0 ${AUX_SYMBOL}`;

  const footerLog = createRollingLog(Math.max(6, toInt(process.env.FOOTER_LOG_LINES, 8)));
  const retryStats = { lastErr: "", lastErrAt: 0, refreshFails: 0, breakerUntil: 0 };

  function setErr(prefix, e) {
    retryStats.lastErr = `${prefix}: ${errToOneLine(e)}`;
    retryStats.lastErrAt = nowMs();
  }

  let refreshEverySec = GLOBAL_REFRESH_EVERY_SEC_BASE;

  function onReadRetry(_attempt, delay, e, label) {
    setErr(label || "retry", e);
    retryStats.refreshFails++;
    if (retryStats.refreshFails >= 3) {
      refreshEverySec = Math.min(GLOBAL_REFRESH_EVERY_SEC_BASE * 6, Math.floor(refreshEverySec * 1.25) + 1);
      if (retryStats.refreshFails >= 8) {
        retryStats.breakerUntil = Math.max(retryStats.breakerUntil, nowMs() + Math.min(30_000, delay * 5));
      }
    }
  }

  async function refreshGlobalSoft() {
    if (retryStats.breakerUntil && nowMs() < retryStats.breakerUntil) {
      throw new Error(`circuit open (cooldown ${(retryStats.breakerUntil - nowMs())}ms)`);
    }

    const res = await withRetryQuiet(
      () =>
        client.v1.chain.get_table_rows({
          json: true,
          code: CONTRACT,
          scope: SCOPE,
          table: TABLE,
          index_position: "primary",
          key_type: "i64",
          lower_bound: GLOBAL_ID,
          limit: 1,
        }),
      { tries: READ_RETRY, label: "refresh_global", onRetry: onReadRetry }
    );

    const row = res?.rows?.[0];
    if (!row) throw new Error("global row not found; did you call init()?");

    const ch =
      typeof row.challenge === "string"
        ? row.challenge
        : row.challenge && typeof row.challenge === "object" && typeof row.challenge.data === "string"
          ? row.challenge.data
          : "";
    const nextChallengeHex = Buffer.from(Checksum256.from(ch).array).toString("hex");

    const nextDiffBits = Number(row.diff_bits ?? 0);
    const nextHeightStr = row.height !== undefined && row.height !== null ? UInt64.from(String(row.height)).toString() : "0";
    const nextTokenContract = String(row.token_contract || TOKEN_CONTRACT_FALLBACK);

    const changed = nextChallengeHex !== challengeHex || nextDiffBits !== diffBits || nextHeightStr !== heightStr;

    tokenContract = nextTokenContract;
    challengeHex = nextChallengeHex;
    diffBits = nextDiffBits;
    heightStr = nextHeightStr;

    retryStats.refreshFails = 0;
    refreshEverySec = Math.max(GLOBAL_REFRESH_EVERY_SEC_BASE, Math.floor(refreshEverySec * 0.85));
    retryStats.breakerUntil = 0;

    return { changed };
  }

  async function refreshAuxBalance() {
    const bal = await withRetryQuiet(
      () => getCurrencyBalanceStringDirect(ENDPOINT, tokenContract, miner, AUX_SYMBOL, READ_TIMEOUT_MS),
      { tries: READ_RETRY, label: "get_aux_balance", onRetry: onReadRetry }
    );
    auxBalanceStr = bal || `0 ${AUX_SYMBOL}`;
  }

  async function buildPackedMineTx(foundNonceBigInt) {
    const info = await withRetryQuiet(() => client.v1.chain.get_info(), {
      tries: READ_RETRY,
      label: "get_info",
      onRetry: onReadRetry,
    });

    const headNum = parseInt(info.head_block_num.toString(), 10);
    const ref_block_num = headNum & 0xffff;
    const ref_block_prefix = refBlockPrefixFromBlockId(info.head_block_id.hexString);

    const expiration = TimePointSec.fromMilliseconds(nowMs() + EXPIRE_SEC * 1000);
    const data = encodeMineActionData(miner, foundNonceBigInt.toString());

    const tx = Transaction.from({
      expiration,
      ref_block_num,
      ref_block_prefix,
      max_net_usage_words: 0,
      max_cpu_usage_ms: 0,
      delay_sec: 0,
      context_free_actions: [],
      actions: [{ account: CONTRACT, name: "mine", authorization: [{ actor: miner, permission: perm }], data }],
      transaction_extensions: [],
    });

    const stx = SignedTransaction.from(tx);
    const digest = tx.signingDigest(info.chain_id);
    stx.signatures = [privateKey.signDigest(digest)];

    return PackedTransaction.fromSigned(stx, COMPRESSION);
  }

  try {
    await refreshGlobalSoft();
  } catch (e) {
    console.error(c("red", "[error]"), `initial refresh_global failed: ${errToOneLine(e)}`);
    process.exit(1);
  }

  try {
    await refreshAuxBalance();
  } catch (e) {
    setErr("AUX init failed", e);
    auxBalanceStr = `0 ${AUX_SYMBOL}`;
  }

  const workerStats = Array.from({ length: THREADS }, () => ({
    hashes: 0,
    bestLz: 0,
    lastHashHex: "",
    lastNonceStr: "",
  }));

  let totalHashesPrev = 0;
  let totalHps = 0;
  let lastHpsAt = nowMs();

  let nonce =
    RANDOM_START
      ? (BigInt("0x" + crypto.randomBytes(8).toString("hex")) & ((1n << 63n) - 1n))
      : BigInt(START_NONCE);

  let workers = [];
  let found = null;

  function makePowHeaderHex() {
    const header = Buffer.allocUnsafe(40);
    Buffer.from(challengeHex, "hex").copy(header, 0);
    minerValueLE.copy(header, 32);
    return header.toString("hex");
  }

  function stopWorkers() {
    for (const w of workers) {
      try {
        w.postMessage({ type: "stop" });
      } catch { }
    }
  }

  async function killWorkers() {
    stopWorkers();
    for (const w of workers) {
      try {
        await w.terminate();
      } catch { }
    }
    workers = [];
  }

  async function respawnWorkers(baseNonce) {
    await killWorkers();

    found = null;
    for (const s of workerStats) {
      s.hashes = 0;
      s.bestLz = 0;
      s.lastHashHex = "";
      s.lastNonceStr = "";
    }
    bestLz = 0;
    lastHashHex = "";
    lastNonceStr = "";

    const headerHex = makePowHeaderHex();
    const step = BigInt(THREADS);

    for (let i = 0; i < THREADS; i++) {
      const start = baseNonce + BigInt(i);
      const w = new Worker(__filename, {
        workerData: {
          workerId: i,
          diffBits,
          powHeaderHex: headerHex,
          startNonceStr: start.toString(),
          stepStr: step.toString(),
          batch: WORKER_BATCH,
          reportEvery: WORKER_REPORT_EVERY,
        },
      });

      w.on("message", (m) => {
        if (!m || typeof m !== "object") return;

        if (m.type === "report") {
          const s = workerStats[m.workerId];
          if (!s) return;
          s.hashes = Number(m.hashes || 0);
          s.bestLz = Math.max(s.bestLz, Number(m.bestLz || 0));
          if (m.lastHashHex) s.lastHashHex = String(m.lastHashHex);
          if (m.lastNonceStr) s.lastNonceStr = String(m.lastNonceStr);

          if (s.bestLz > bestLz) bestLz = s.bestLz;
          if (s.lastHashHex) {
            lastHashHex = s.lastHashHex;
            lastNonceStr = s.lastNonceStr;
          }
        }

        if (m.type === "found" && !found) {
          found = { workerId: m.workerId, nonce: String(m.nonce), lz: Number(m.lz), hashHex: String(m.hashHex) };
        }
      });

      w.on("error", (e) => setErr(`Worker ${i} error`, e));
      workers.push(w);
    }
  }

  await respawnWorkers(nonce);

  const modeText = privateKey ? (BROADCAST_ON ? "auto-push" : "sign-only") : "search-only";

  let lastGlobalRefreshAt = nowMs();

  const SPIN = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
  let spinIdx = 0;

  function miningFooterBase() {
    return `Mining… refresh=${refreshEverySec}s • THREADS=${THREADS}`;
  }

  function footerLine(now) {
    void now;
    return `${SPIN[spinIdx]} ${miningFooterBase()}`;
  }

  function computeHps(now) {
    const totalHashes = workerStats.reduce((a, s) => a + (s.hashes || 0), 0);
    const dt = (now - lastHpsAt) / 1000;
    if (dt >= HPS_REFRESH_MS / 1000) {
      totalHps = (totalHashes - totalHashesPrev) / Math.max(0.001, dt);
      totalHashesPrev = totalHashes;
      lastHpsAt = now;
    }
  }

  function redraw(now) {
    computeHps(now);
    spinIdx = (spinIdx + 1) % SPIN.length;

    const uptimeSec = Math.floor((now - startTime) / 1000);

    const dash = buildDashboardLines({
      endpoint: ENDPOINT,
      contract: CONTRACT,
      miner,
      perm,
      mode: modeText,
      threads: THREADS,
      pcSpec,
      heightStr,
      diffBits,
      challengeHex,
      bestLz,
      lastHashHex,
      lastNonceStr,
      foundCount,
      pushedCount,
      failedCount,
      totalHps,
      uptimeSec,
      footerLine: footerLine(now),
      auxBalanceStr,
      auxSymbol: AUX_SYMBOL,
      footerLogLines: footerLog.lines(),
    });

    renderer.render(dash);
  }

  let lastLogAt = 0;
  function logCompact(now) {
    if (isTTY) return;
    if (now - lastLogAt < 5000) return;
    lastLogAt = now;
    const tail = footerLog.lines().slice(-1)[0] || "";
    const msg =
      `[miner] h=${heightStr} diff=${diffBits} best=${bestLz} ` +
      `hps=${formatHps(totalHps)} found=${foundCount} pushed=${pushedCount} failed=${failedCount} ` +
      `AUX=${auxBalanceStr}` +
      (tail ? ` | ${tail.replace(/\x1b\[[0-9;]*m/g, "")}` : "");
    console.log(msg);
  }

  async function loop() {
    while (!stop) {
      const now = nowMs();

      if (now - lastGlobalRefreshAt >= refreshEverySec * 1000) {
        lastGlobalRefreshAt = now;
        try {
          const { changed } = await refreshGlobalSoft();
          if (changed) {
            footerLog.push(c("gray", `• New work: height=${heightStr} diff=${diffBits} challenge=${shortHex(challengeHex, 32)}`));
            await respawnWorkers(nonce);
          }
        } catch (e) {
          setErr("Global refresh failed", e);
          footerLog.push(c("red", `• Global refresh failed: ${errToOneLine(e)}`));
        }
      }

      if (found) {
        const f = found;
        found = null;

        foundCount++;
        stopWorkers();

        footerLog.push(`${c("green", "★ FOUND")} ${c("bold", `nonce=${f.nonce}`)}  ${c("gray", `lz=${f.lz} ≥ ${diffBits}`)}`);
        footerLog.push(`${c("gray", "  hash")}  ${c("cyan", shortHex(f.hashHex, 64))}`);
        footerLog.push(c("gray", "  … reading AUX balance (FOUND)"));
        redraw(nowMs());

        try {
          await refreshAuxBalance();
          footerLog.setLast(c("green", `  ✔ AUX updated: ${auxBalanceStr}`));
        } catch (e) {
          setErr("AUX FOUND failed", e);
          footerLog.setLast(c("red", `  ✖ AUX refresh failed: ${errToOneLine(e)}`));
        }
        redraw(nowMs());

        if (!privateKey) {
          footerLog.push(c("yellow", "  [NOTE] PRIVATE_KEY not set; search-only (continue mining)"));
          nonce = BigInt(f.nonce) + 1n;
          await sleep(200);
          await respawnWorkers(nonce);
          lastGlobalRefreshAt = nowMs();
          redraw(nowMs());
          await sleep(UI_TICK_MS);
          continue;
        }

        footerLog.push(c("gray", `  … building tx (mine ${miner}@${perm})`));
        redraw(nowMs());

        try {
          const packed = await buildPackedMineTx(BigInt(f.nonce));
          footerLog.setLast(c("green", "  ✔ TX built & signed"));
          redraw(nowMs());

          if (!BROADCAST_ON) {
            footerLog.push(c("yellow", "  [TX] signed (BROADCAST=0)."));
          } else {
            footerLog.push(c("gray", "  … pushing tx"));
            redraw(nowMs());

            try {
              const pushed = await withRetryQuiet(() => client.v1.chain.push_transaction(packed), {
                tries: PUSH_RETRY,
                label: "push_tx",
                onRetry: onReadRetry,
              });
              pushedCount++;
              footerLog.setLast(c("green", `  ✔ Accepted: txid=${pushed.transaction_id}`));
            } catch (e) {
              if (isTaposOrExpired(e)) {
                footerLog.setLast(c("yellow", "  … TAPOS/expired, rebuilding once"));
                redraw(nowMs());
                try {
                  const packed2 = await buildPackedMineTx(BigInt(f.nonce));
                  const pushed2 = await withRetryQuiet(() => client.v1.chain.push_transaction(packed2), {
                    tries: PUSH_RETRY,
                    label: "push_tx2",
                    onRetry: onReadRetry,
                  });
                  pushedCount++;
                  footerLog.setLast(c("green", `  ✔ Accepted (rebuild): txid=${pushed2.transaction_id}`));
                } catch (e2) {
                  failedCount++;
                  setErr("push(rebuild) failed", e2);
                  footerLog.setLast(c("red", `  ✖ Push failed (rebuild): ${errToOneLine(e2)}`));
                }
              } else {
                failedCount++;
                setErr("push failed", e);
                footerLog.setLast(c("red", `  ✖ Push failed: ${errToOneLine(e)}`));
              }
            }
          }
        } catch (e) {
          failedCount++;
          setErr("build/sign failed", e);
          footerLog.setLast(c("red", `  ✖ Build/sign failed: ${errToOneLine(e)}`));
        }

        // continue mining
        nonce = BigInt(f.nonce) + 1n;
        await sleep(250);
        await respawnWorkers(nonce);
        lastGlobalRefreshAt = nowMs();
      }

      redraw(now);
      logCompact(now);

      await sleep(UI_TICK_MS);
    }

    await killWorkers();
    renderer.close();
    process.stdout.write(c("yellow", "[exit] stopped.\n"));
    process.exit(0);
  }

  try {
    await loop();
  } finally {
    renderer.close();
  }
}

main().catch((e) => {
  try {
    if (process.stdout.isTTY) process.stdout.write(ANSI.showCursor);
  } catch { }
  process.stdout.write("\n");
  console.error(c("red", "[error]"), errToOneLine(e));
  if (e?.json) console.error(c("gray", "details:"), e.json);
  process.exit(1);
});