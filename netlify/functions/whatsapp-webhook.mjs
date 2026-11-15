import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

// WhatsApp Cloud API webhook receiver for Grupo Multiple.
// GET  = Meta verification handshake (hub.mode / hub.verify_token / hub.challenge)
// POST = incoming WhatsApp events, stored in Netlify Blobs store "whatsapp-inbox".
//
// Auth model: the expected verify token is read from the WHATSAPP_VERIFY_TOKEN
// env var when set. Until the env var is configured in the Netlify dashboard,
// a SHA-256 hash fallback is used so the raw token never lives in this repo.
const VERIFY_TOKEN_SHA256 = "34e955ed78d7d8964ec21d9692d5e3e709ee110842beab1cd164a94c52c97c08";

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function verifyTokenOk(candidate) {
  if (!candidate) return false;
  const expected = process.env.WHATSAPP_VERIFY_TOKEN;
  if (expected) return safeEqual(candidate, expected);
  return safeEqual(sha256Hex(candidate), VERIFY_TOKEN_SHA256);
}

export default async (req) => {
  const url = new URL(req.url);

  if (req.method === "GET") {
    const mode = url.searchParams.get("hub.mode");
    const token = url.searchParams.get("hub.verify_token");
    const challenge = url.searchParams.get("hub.challenge");
    if (mode === "subscribe" && verifyTokenOk(token)) {
      return new Response(challenge ?? "", {
        status: 200,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }
    return new Response("Forbidden", { status: 403 });
  }

  if (req.method === "POST") {
    let payload;
    try {
      payload = await req.json();
    } catch {
      return new Response("Bad Request", { status: 400 });
    }

    const receivedAt = new Date().toISOString();
    const records = [];
    for (const entry of payload.entry ?? []) {
      for (const change of entry.changes ?? []) {
        const value = change.value ?? {};
        const metadata = value.metadata ?? {};
        for (const message of value.messages ?? []) {
          records.push({
            kind: "message",
            received_at: receivedAt,
            waba_id: entry.id ?? null,
            phone_number_id: metadata.phone_number_id ?? null,
            display_phone_number: metadata.display_phone_number ?? null,
            contacts: value.contacts ?? [],
            message,
          });
        }
        for (const statusEvent of value.statuses ?? []) {
          records.push({
            kind: "status",
            received_at: receivedAt,
            waba_id: entry.id ?? null,
            phone_number_id: metadata.phone_number_id ?? null,
            status_event: statusEvent,
          });
        }
      }
    }
    const toStore = records.length
      ? records
      : [{ kind: "raw", received_at: receivedAt, payload }];

    try {
      const store = getStore("whatsapp-inbox");
      for (const record of toStore) {
        const rawId =
          record.message?.id ?? record.status_event?.id ?? crypto.randomUUID();
        const idPart = String(rawId).replace(/[^a-zA-Z0-9-_]/g, "_");
        const key = `${Date.now()}-${idPart}`;
        await store.setJSON(key, record);
      }
    } catch (err) {
      console.error("blob store failed", err);
      // Still answer 200 so Meta does not retry-storm; the error is logged.
    }
    return new Response("EVENT_RECEIVED", { status: 200 });
  }

  return new Response("Method Not Allowed", { status: 405 });
};
