import { useState, useEffect, useRef, useCallback } from 'react';

export interface AgentEvent {
  id: string;
  type: string;
  event: string;
  path: string;
  time: number;
  receivedAt: Date;
}

interface UseAgentTelemetryOptions {
  url: string;
  enabled: boolean;
}

export const useAgentTelemetry = ({ url, enabled }: UseAgentTelemetryOptions) => {
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const connect = useCallback(() => {
    if (!enabled || !url) return;

    try {
      setError(null);
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
        setError(null);
      };

      ws.onmessage = (msg) => {
        try {
          const data = JSON.parse(msg.data);
          const agentEvent: AgentEvent = {
            id: Date.now().toString() + Math.random().toString(36).substr(2, 6),
            type: data.type || 'unknown',
            event: data.event || 'unknown',
            path: data.path || '',
            time: data.time || Date.now(),
            receivedAt: new Date(),
          };
          setEvents(prev => [agentEvent, ...prev.slice(0, 99)]);
        } catch {
          // ignore malformed messages
        }
      };

      ws.onclose = () => {
        setConnected(false);
        // Auto-reconnect after 3s
        if (enabled) {
          reconnectRef.current = setTimeout(connect, 3000);
        }
      };

      ws.onerror = () => {
        setError('Cannot connect to agent backend');
        setConnected(false);
      };
    } catch {
      setError('Invalid WebSocket URL');
    }
  }, [url, enabled]);

  useEffect(() => {
    if (enabled) {
      connect();
    }
    return () => {
      wsRef.current?.close();
      if (reconnectRef.current) clearTimeout(reconnectRef.current);
    };
  }, [connect, enabled]);

  const clearEvents = useCallback(() => setEvents([]), []);

  return { events, connected, error, clearEvents };
};
