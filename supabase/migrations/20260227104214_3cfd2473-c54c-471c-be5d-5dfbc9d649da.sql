
CREATE TABLE public.agent_telemetry (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  event TEXT NOT NULL,
  path TEXT NOT NULL,
  hostname TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS but allow public inserts (agent has no auth) and reads
ALTER TABLE public.agent_telemetry ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow public insert" ON public.agent_telemetry FOR INSERT WITH CHECK (true);
CREATE POLICY "Allow public select" ON public.agent_telemetry FOR SELECT USING (true);

-- Auto-delete old events (keep last 500)
CREATE OR REPLACE FUNCTION cleanup_old_telemetry()
RETURNS TRIGGER AS $$
BEGIN
  DELETE FROM public.agent_telemetry
  WHERE id NOT IN (
    SELECT id FROM public.agent_telemetry ORDER BY created_at DESC LIMIT 500
  );
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_cleanup_telemetry
AFTER INSERT ON public.agent_telemetry
FOR EACH STATEMENT
EXECUTE FUNCTION cleanup_old_telemetry();

-- Enable realtime
ALTER PUBLICATION supabase_realtime ADD TABLE public.agent_telemetry;
