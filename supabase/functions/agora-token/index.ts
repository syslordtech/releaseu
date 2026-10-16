// Issues a short-lived Agora token ONLY to the two people in an active call.
// Secrets (set in Supabase > Edge Functions > Secrets): AGORA_APP_ID, AGORA_APP_CERTIFICATE
import { createClient } from "npm:@supabase/supabase-js@2";
import { RtcTokenBuilder, RtcRole } from "npm:agora-token@2.0.3";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const sb = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_ANON_KEY")!, {
      global: { headers: { Authorization: req.headers.get("Authorization") ?? "" } },
    });
    const { callId } = await req.json();
    const { data, error } = await sb.rpc("call_token_info", { p_call_id: callId });
    if (error || !data) return json({ error: "not allowed" }, 403);

    const appId = Deno.env.get("AGORA_APP_ID")!;
    const cert = Deno.env.get("AGORA_APP_CERTIFICATE")!;
    const remaining = Math.max(5, Math.floor(data.remaining));   // token dies when the demo / balance runs out
    const token = RtcTokenBuilder.buildTokenWithUid(appId, cert, data.channel, data.uid, RtcRole.PUBLISHER, remaining, remaining);
    return json({ appId, channel: data.channel, uid: data.uid, token, remaining });
  } catch (_e) {
    return json({ error: "failed" }, 500);
  }
});
