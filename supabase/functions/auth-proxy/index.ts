const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { action, email, password, redirectTo } = await req.json();
    const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
    const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY")!;

    let url: string;
    let body: Record<string, unknown>;

    if (action === "signup") {
      url = `${SUPABASE_URL}/auth/v1/signup`;
      body = {
        email,
        password,
        data: {},
        gotrue_meta_security: {},
      };
      if (redirectTo) {
        (body as any).code_challenge_method = undefined;
        // GoTrue uses redirect in options
      }
    } else if (action === "login") {
      url = `${SUPABASE_URL}/auth/v1/token?grant_type=password`;
      body = { email, password, gotrue_meta_security: {} };
    } else {
      return new Response(
        JSON.stringify({ error: "Invalid action. Use 'login' or 'signup'" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        apikey: SUPABASE_ANON_KEY,
        Authorization: `Bearer ${SUPABASE_ANON_KEY}`,
      },
      body: JSON.stringify(body),
    });

    const data = await response.json();

    return new Response(JSON.stringify(data), {
      status: response.status,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (err) {
    return new Response(
      JSON.stringify({ error: (err as Error).message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
