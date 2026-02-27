
CREATE OR REPLACE FUNCTION public.cleanup_old_telemetry()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
  DELETE FROM public.agent_telemetry
  WHERE id NOT IN (
    SELECT id FROM public.agent_telemetry ORDER BY created_at DESC LIMIT 500
  );
  RETURN NEW;
END;
$$;
