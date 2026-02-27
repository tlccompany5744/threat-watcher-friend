import { useState, useEffect, useCallback } from 'react';
import { supabase } from '@/integrations/supabase/client';

export interface AgentEvent {
  id: string;
  type: string;
  event: string;
  path: string;
  time: number;
  receivedAt: Date;
}

interface UseAgentTelemetryOptions {
  enabled: boolean;
}

export const useAgentTelemetry = ({ enabled }: UseAgentTelemetryOptions) => {
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!enabled) {
      setConnected(false);
      return;
    }

    setError(null);

    // Load recent events
    const loadRecent = async () => {
      const { data, error: fetchErr } = await supabase
        .from('agent_telemetry')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(50);

      if (fetchErr) {
        setError('Failed to load telemetry');
        return;
      }

      if (data) {
        setEvents(data.map((row: any) => ({
          id: row.id,
          type: 'file_event',
          event: row.event,
          path: row.path,
          time: new Date(row.created_at).getTime(),
          receivedAt: new Date(row.created_at),
        })));
      }
    };

    loadRecent();

    // Subscribe to realtime inserts
    const channel = supabase
      .channel('agent-telemetry-live')
      .on(
        'postgres_changes',
        { event: 'INSERT', schema: 'public', table: 'agent_telemetry' },
        (payload) => {
          const row = payload.new as any;
          const agentEvent: AgentEvent = {
            id: row.id,
            type: 'file_event',
            event: row.event,
            path: row.path,
            time: new Date(row.created_at).getTime(),
            receivedAt: new Date(row.created_at),
          };
          setEvents(prev => [agentEvent, ...prev.slice(0, 99)]);
        }
      )
      .subscribe((status) => {
        if (status === 'SUBSCRIBED') {
          setConnected(true);
          setError(null);
        } else if (status === 'CHANNEL_ERROR') {
          setError('Realtime connection failed');
          setConnected(false);
        }
      });

    return () => {
      supabase.removeChannel(channel);
      setConnected(false);
    };
  }, [enabled]);

  const clearEvents = useCallback(() => setEvents([]), []);

  return { events, connected, error, clearEvents };
};
