import { createHmac, timingSafeEqual } from "node:crypto";
import { getStore } from "@netlify/blobs";

const COOKIE = "kredit_edit";
const STORE = "kredit-200000";
const EDIT_PASSWORD = "guan";
const MAX_BODY = 300000;
const MAX_PAYMENTS = 2000;

export const config = { path: ["/api/state", "/api/session"] };

export default async function handler(req) {
  try {
    const path = new URL(req.url).pathname.replace(/\/+$/, "");
    if (path === "/api/session") {
      if (req.method === "GET") return json({ editor: authed(req) });
      if (req.method === "DELETE") return json({ editor: false }, 200, clearCookie(req));
      if (req.method === "POST") return login(req);
    }
    if (path === "/api/state") {
      const store = getStore({ name: STORE, consistency: "strong" });
      if (req.method === "GET") return json(await readState(store));
      if (req.method === "PUT") return putState(req, store);
    }
    return json({ error: "Не найдено." }, 404);
  } catch (error) {
    console.error(error);
    return json({ error: "Журнал временно недоступен.", code: String(error?.name || "Error") }, 500);
  }
}

function json(data, status = 200, cookie) {
  const headers = new Headers({
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  if (cookie) headers.append("set-cookie", cookie);
  return new Response(JSON.stringify(data), { status, headers });
}

function sessionToken() {
  return createHmac("sha256", EDIT_PASSWORD).update("kredit-edit-v1").digest("base64url");
}

function readCookie(req, name) {
  for (const part of (req.headers.get("cookie") || "").split(";")) {
    const text = part.trim();
    const eq = text.indexOf("=");
    if (eq !== -1 && text.slice(0, eq) === name) return text.slice(eq + 1);
  }
  return "";
}

function sameText(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  const len = Math.max(left.length, right.length, 1);
  const x = Buffer.alloc(len);
  const y = Buffer.alloc(len);
  left.copy(x);
  right.copy(y);
  return left.length === right.length && timingSafeEqual(x, y);
}

function authed(req) {
  const got = readCookie(req, COOKIE);
  return Boolean(got) && sameText(got, sessionToken());
}

function secureFlag(req) {
  return new URL(req.url).protocol === "https:" ? "; Secure" : "";
}

function sessionCookie(req) {
  return `${COOKIE}=${sessionToken()}; HttpOnly; Path=/; SameSite=Lax${secureFlag(req)}`;
}

function clearCookie(req) {
  return `${COOKIE}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0${secureFlag(req)}`;
}

function clientIp(req) {
  return req.headers.get("x-nf-client-connection-ip")
    || (req.headers.get("x-forwarded-for") || "").split(",")[0].trim()
    || "local";
}

async function login(req) {
  let body = {};
  try { body = JSON.parse((await req.text()) || "{}"); } catch (e) { body = {}; }
  if (sameText(body.password || "", EDIT_PASSWORD)) {
    return json({ editor: true }, 200, sessionCookie(req));
  }
  // Ограничение подбора пароля. Если хранилище недоступно, всё равно отказываем.
  try {
    const store = getStore({ name: STORE, consistency: "strong" });
    const lockKey = "lock:" + createHmac("sha256", "kredit-lock").update(clientIp(req)).digest("hex").slice(0, 24);
    const row = (await store.get(lockKey, { type: "json" })) || { fails: 0, until: 0 };
    if (row.until > Date.now()) return json({ error: "Слишком много попыток. Подождите 15 минут." }, 429);
    const fails = (row.until && row.until < Date.now() ? 0 : row.fails) + 1;
    const until = fails >= 8 ? Date.now() + 15 * 60 * 1000 : 0;
    await store.setJSON(lockKey, { fails: until ? 0 : fails, until });
  } catch (error) {
    console.error(error);
  }
  await new Promise((resolve) => setTimeout(resolve, 300));
  return json({ error: "Неверный пароль." }, 401);
}

async function readState(store) {
  const data = await store.get("state", { type: "json" });
  if (!data) return { settings: null, payments: [], deletedIds: [], updatedAt: null };
  return {
    settings: data.settings || null,
    payments: Array.isArray(data.payments) ? data.payments : [],
    deletedIds: Array.isArray(data.deletedIds) ? data.deletedIds : [],
    updatedAt: data.updatedAt || null,
  };
}

function validDate(value) {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(value || ""));
  if (!match) return false;
  const y = Number(match[1]);
  const m = Number(match[2]);
  const d = Number(match[3]);
  const date = new Date(Date.UTC(y, m - 1, d));
  return date.getUTCFullYear() === y && date.getUTCMonth() === m - 1 && date.getUTCDate() === d;
}

function cleanSettings(raw) {
  if (!raw || typeof raw !== "object") return null;
  const amount = Number(raw.amount);
  const monthly = Number(raw.monthly);
  const sms = Number(raw.sms);
  const rate1 = Number(raw.rate1);
  const rate2 = Number(raw.rate2);
  const paymentDay = Number(raw.paymentDay);
  const dueRule = raw.dueRule === "fixedDay" ? "fixedDay" : "lastBusinessDay";
  const firstInterestStart = validDate(raw.firstInterestStart) ? raw.firstInterestStart : raw.start;
  const principalMonths = Number(raw.principalMonths);
  const preferentialDays = Number(raw.preferentialDays);
  const graceMonths = Number(raw.graceMonths);
  const termYears = Number(raw.termYears);
  if (!(amount > 0 && amount <= 100000000)) return null;
  if (!(monthly > 0 && monthly <= 100000000)) return null;
  if (!(sms >= 0 && sms <= 50)) return null;
  if (!(rate1 > 0 && rate1 <= 100 && rate2 > 0 && rate2 <= 100)) return null;
  if (!Number.isInteger(paymentDay) || paymentDay < 1 || paymentDay > 31) return null;
  if (!Number.isInteger(preferentialDays) || preferentialDays < 0 || preferentialDays > 3650) return null;
  if (!Number.isInteger(graceMonths) || graceMonths < 0 || graceMonths > 120) return null;
  if (!Number.isInteger(termYears) || termYears < 1 || termYears > 40) return null;
  if (!validDate(raw.start)) return null;
  if (!Number.isInteger(principalMonths) || principalMonths < 1 || principalMonths > termYears * 12) return null;
  return {
    amount,
    start: raw.start,
    paymentDay,
    dueRule,
    firstInterestStart,
    smsStart: validDate(raw.smsStart) ? raw.smsStart : firstInterestStart,
    rate1,
    rate2,
    preferentialDays,
    graceMonths,
    principalMonths,
    termYears,
    yearBase: Number(raw.yearBase) === 360 ? 360 : 365,
    monthly,
    sms,
  };
}

function cleanPayment(raw) {
  if (!raw || typeof raw !== "object") return null;
  const id = String(raw.id || "");
  if (!/^[\w-]{8,80}$/.test(id)) return null;
  if (!validDate(raw.date)) return null;
  const amountKop = Number(raw.amountKop);
  if (!Number.isInteger(amountKop) || amountKop <= 0 || amountKop > 1e12) return null;
  return { id, date: raw.date, amountKop, smsKop: 0, note: String(raw.note || "").slice(0, 200) };
}

async function putState(req, store) {
  if (!authed(req)) return json({ error: "Нужен пароль." }, 401);
  const text = await req.text();
  if (text.length > MAX_BODY) return json({ error: "Слишком большой журнал." }, 413);
  let body;
  try { body = JSON.parse(text); } catch (e) { return json({ error: "Журнал не разобран." }, 400); }
  const settings = cleanSettings(body.settings);
  if (!settings) return json({ error: "Проверьте условия кредита." }, 400);
  if (!Array.isArray(body.payments) || body.payments.length > MAX_PAYMENTS) {
    return json({ error: "Проверьте список платежей." }, 400);
  }
  const payments = [];
  for (const item of body.payments) {
    const clean = cleanPayment(item);
    if (!clean) return json({ error: "В журнале есть некорректный платёж." }, 400);
    payments.push(clean);
  }
  const deletedIds = Array.isArray(body.deletedIds)
    ? body.deletedIds.map((id) => String(id).slice(0, 80)).slice(0, MAX_PAYMENTS)
    : [];
  const current = await readState(store);
  if ((body.updatedAt || null) !== current.updatedAt) {
    return json({ error: "Журнал уже изменён. Обновите страницу." }, 409);
  }
  const updatedAt = new Date().toISOString();
  await store.setJSON("state", { settings, payments, deletedIds, updatedAt });
  return json({ updatedAt });
}
