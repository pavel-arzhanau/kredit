import { createHmac, timingSafeEqual } from "node:crypto";
import { getStore } from "@netlify/blobs";

const COOKIE = "kredit_edit";
const STORE = "kredit-200000";
const EDIT_PASSWORD = "guan";
const MAX_BODY = 300000;
const MAX_PAYMENTS = 2000;

export async function handler(event) {
  try {
    const path = routeOf(event);
    const store = getStore({ name: STORE, consistency: "strong" });
    if (event.httpMethod === "GET" && path === "/api/state") return json(await readState(store));
    if (event.httpMethod === "PUT" && path === "/api/state") return putState(event, store);
    if (event.httpMethod === "GET" && path === "/api/session") return json({ editor: authed(event) });
    if (event.httpMethod === "POST" && path === "/api/session") return login(event, store);
    if (event.httpMethod === "DELETE" && path === "/api/session") return logout(event);
    return json({ error: "Не найдено." }, 404);
  } catch (error) {
    console.error(error);
    return json({ error: "Журнал временно недоступен." }, 500);
  }
}

function routeOf(event) {
  const path = String(event.path || "/").replace(/\/+$/, "") || "/";
  if (path.startsWith("/api")) return path;
  const marker = "/.netlify/functions/kredit";
  if (path === marker) return "/api";
  if (path.startsWith(marker + "/")) return "/api" + path.slice(marker.length);
  return path;
}

function json(data, status, cookie) {
  const headers = {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  };
  const response = { statusCode: status || 200, headers, body: JSON.stringify(data) };
  if (cookie) response.multiValueHeaders = { "set-cookie": [cookie] };
  return response;
}

function password() {
  return EDIT_PASSWORD;
}

function sessionToken(secret) {
  return createHmac("sha256", secret).update("kredit-edit-v1").digest("base64url");
}

function readCookie(event, name) {
  const raw = event.headers?.cookie || event.headers?.Cookie || "";
  for (const part of raw.split(";")) {
    const text = part.trim();
    const eq = text.indexOf("=");
    if (eq === -1) continue;
    if (text.slice(0, eq) === name) return text.slice(eq + 1);
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

function authed(event) {
  const secret = password();
  if (!secret) return false;
  const got = readCookie(event, COOKIE);
  if (!got) return false;
  return sameText(got, sessionToken(secret));
}

function https(event) {
  const proto = event.headers?.["x-forwarded-proto"] || "";
  return proto.split(",")[0].trim() === "https" || String(event.rawUrl || "").startsWith("https:");
}

function sessionCookie(event, token) {
  const secure = https(event) ? "; Secure" : "";
  return `${COOKIE}=${token}; HttpOnly; Path=/; SameSite=Lax${secure}`;
}

function clearCookie(event) {
  const secure = https(event) ? "; Secure" : "";
  return `${COOKIE}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0${secure}`;
}

function clientIp(event) {
  return event.headers?.["x-nf-client-connection-ip"]
    || String(event.headers?.["x-forwarded-for"] || "").split(",")[0].trim()
    || "local";
}

async function login(event, store) {
  const secret = password();
  if (!secret) return json({ error: "Пароль правок не задан в настройках сайта." }, 503);
  const ip = clientIp(event);
  const lockKey = "lock:" + createHmac("sha256", "kredit-lock").update(ip).digest("hex").slice(0, 24);
  const row = (await store.get(lockKey, { type: "json" })) || { fails: 0, until: 0 };
  if (row.until > Date.now()) return json({ error: "Слишком много попыток. Подождите 15 минут." }, 429);
  let body = {};
  try { body = JSON.parse(event.body || "{}"); } catch (e) { body = {}; }
  if (!sameText(body.password || "", secret)) {
    const fails = (row.until && row.until < Date.now() ? 0 : row.fails) + 1;
    const until = fails >= 8 ? Date.now() + 15 * 60 * 1000 : 0;
    await store.setJSON(lockKey, { fails: until ? 0 : fails, until });
    await new Promise((resolve) => setTimeout(resolve, 300));
    return json({ error: "Неверный пароль." }, 401);
  }
  await store.delete(lockKey);
  return json({ editor: true }, 200, sessionCookie(event, sessionToken(secret)));
}

function logout(event) {
  return json({ editor: false }, 200, clearCookie(event));
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
  return {
    amount,
    start: raw.start,
    paymentDay,
    rate1,
    rate2,
    preferentialDays,
    graceMonths,
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
  const smsKop = Number(raw.smsKop || 0);
  if (!Number.isInteger(smsKop) || smsKop < 0 || smsKop > amountKop) return null;
  return { id, date: raw.date, amountKop, smsKop, note: String(raw.note || "").slice(0, 200) };
}

async function putState(event, store) {
  if (!password()) return json({ error: "Пароль правок не задан в настройках сайта." }, 503);
  if (!authed(event)) return json({ error: "Нужен пароль." }, 401);
  const text = event.body || "";
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
  const sent = body.updatedAt || null;
  if (sent !== current.updatedAt) return json({ error: "Журнал уже изменён. Обновите страницу." }, 409);
  const updatedAt = new Date().toISOString();
  await store.setJSON("state", { settings, payments, deletedIds, updatedAt });
  return json({ updatedAt });
}
