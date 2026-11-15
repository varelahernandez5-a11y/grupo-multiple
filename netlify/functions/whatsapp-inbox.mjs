import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

// Protected reader for the WhatsApp inbox stored by whatsapp-webhook.
// GET    -> JSON list of stored events, newest first. Params: since (ISO date
//           or epoch ms), limit (default 100).
// DELETE -> remove one event with ?key=<blob key>.
// Auth: header "x-inbox-secret" or query param "secret". The expected value is
// read from the WHATSAPP_INBOX_SECRET env var when set. Until the env var is
// configured in the Netlify dashboard, a SHA-256 hash fallback is used so the
// raw secret never lives in this repo.
const INBOX_SECRET_SHA256 = "06a953434b2bb346b2cec9b06809531790cf8b80e2d61a8d10bc66c9345aa9d8";

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function secretOk(candidate) {
  if (!candidate) return false;
  const expected = process.env.WHATSAPP_INBOX_SECRET;
  if (expected) return safeEqual(candidate, expected);
  return safeEqual(sha256Hex(candidate), INBOX_SECRET_SHA256);
}

export default async (req) => {
  const url = new URL(req.url);
  const candidate =
    req.headers.get("x-inbox-secret") ?? url.searchParams.get("secret");
  if (!secretOk(candidate)) {
    return new Response(JSON.stringify({ error: "unauthorized" }), {
      status: 401,
      headers: { "content-type": "application/json" },
    });
  }

  const store = getStore("whatsapp-inbox");

  if (req.method === "DELETE") {
    const key = url.searchParams.get("key");
    if (!key) {
      return new Response(JSON.stringify({ error: "missing key" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      });
    }
    await store.delete(key);
    return new Response(JSON.stringify({ deleted: key }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }

  if (req.method !== "GET") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  const sinceRaw = url.searchParams.get("since");
  let sinceMs = 0;
  if (sinceRaw) {
    const asNumber = Number(sinceRaw);
    sinceMs = Number.isFinite(asNumber) && asNumber > 0
      ? asNumber
      : Date.parse(sinceRaw) || 0;
  }
  const limit = Math.min(
    Math.max(parseInt(url.searchParams.get("limit") ?? "100", 10) || 100, 1),
    500
  );

  const { blobs } = await store.list();
  const events = [];
  for (const blob of blobs) {
    const data = await store.get(blob.key, { type: "json" });
    if (!data) continue;
    const receivedMs = Date.parse(data.received_at ?? "") || 0;
    if (receivedMs < sinceMs) continue;
    events.push({ key: blob.key, ...data });
  }
  events.sort((a, b) => (Date.parse(b.received_at) || 0) - (Date.parse(a.received_at) || 0));

  return new Response(
    JSON.stringify({ count: events.length, events: events.slice(0, limit) }),
    { status: 200, headers: { "content-type": "application/json" } }
  );
};
