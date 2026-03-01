import { createContext, useContext, useEffect, useState, useRef, useCallback, ReactNode } from 'react';
import { User, Session } from '@supabase/supabase-js';
import { supabase } from '@/integrations/supabase/client';
import { toast } from '@/hooks/use-toast';

const SESSION_TIMEOUT_MS = 5 * 60 * 1000;
const WARNING_BEFORE_MS = 60 * 1000;

interface AuthContextType {
  user: User | null;
  session: Session | null;
  loading: boolean;
  signIn: (email: string, password: string) => Promise<{ error: Error | null }>;
  signUp: (email: string, password: string) => Promise<{ error: Error | null }>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [user, setUser] = useState<User | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  const logoutTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const warningTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const warningShownRef = useRef(false);
  const userRef = useRef<User | null>(null);

  // Keep ref in sync
  useEffect(() => {
    userRef.current = user;
  }, [user]);

  const clearTimers = useCallback(() => {
    if (logoutTimerRef.current) { clearTimeout(logoutTimerRef.current); logoutTimerRef.current = null; }
    if (warningTimerRef.current) { clearTimeout(warningTimerRef.current); warningTimerRef.current = null; }
    warningShownRef.current = false;
  }, []);

  const performSignOut = useCallback(async () => {
    clearTimers();
    try {
      await supabase.auth.signOut();
    } catch (err) {
      console.error('Sign out error:', err);
    }
    // Force clear state in case onAuthStateChange doesn't fire
    setUser(null);
    setSession(null);
    // Navigate to auth
    window.location.href = '/auth';
  }, [clearTimers]);

  const resetInactivityTimer = useCallback(() => {
    if (!userRef.current) return;
    clearTimers();

    warningTimerRef.current = setTimeout(() => {
      if (!warningShownRef.current) {
        warningShownRef.current = true;
        toast({
          title: "⏱️ Session Expiring Soon",
          description: "You will be logged out in 1 minute due to inactivity.",
        });
      }
    }, SESSION_TIMEOUT_MS - WARNING_BEFORE_MS);

    logoutTimerRef.current = setTimeout(() => {
      toast({
        title: "⚠️ Session Expired",
        description: "Logged out due to inactivity.",
        variant: "destructive",
      });
      performSignOut();
    }, SESSION_TIMEOUT_MS);
  }, [clearTimers, performSignOut]);

  // Activity listeners
  useEffect(() => {
    if (!user) {
      clearTimers();
      return;
    }

    const handleActivity = () => {
      warningShownRef.current = false;
      resetInactivityTimer();
    };

    const events = ['mousedown', 'keydown', 'scroll', 'touchstart', 'mousemove'];
    events.forEach(e => window.addEventListener(e, handleActivity, { passive: true }));
    resetInactivityTimer();

    return () => {
      events.forEach(e => window.removeEventListener(e, handleActivity));
      clearTimers();
    };
  }, [user, resetInactivityTimer, clearTimers]);

  useEffect(() => {
    const { data: { subscription } } = supabase.auth.onAuthStateChange(
      (event, session) => {
        setSession(session);
        setUser(session?.user ?? null);
        setLoading(false);
      }
    );

    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      setUser(session?.user ?? null);
      setLoading(false);
    });

    return () => subscription.unsubscribe();
  }, []);

  const signIn = async (email: string, password: string) => {
    try {
      const { error } = await supabase.auth.signInWithPassword({ email, password });
      return { error: error as Error | null };
    } catch (directError: any) {
      // If direct call fails (e.g. iframe CORS), use the proxy edge function
      console.log('Direct auth failed, using proxy...', directError?.message);
      try {
        const { data, error: fnError } = await supabase.functions.invoke('auth-proxy', {
          body: { action: 'login', email, password },
        });
        if (fnError) return { error: new Error(fnError.message) };
        if (data?.error) return { error: new Error(data.error_description || data.error || data.msg) };
        if (data?.access_token) {
          // Set the session manually from the proxy response
          const { error: setError } = await supabase.auth.setSession({
            access_token: data.access_token,
            refresh_token: data.refresh_token,
          });
          return { error: setError as Error | null };
        }
        return { error: new Error('Authentication failed') };
      } catch (proxyError: any) {
        return { error: new Error(proxyError?.message || 'Authentication failed') };
      }
    }
  };

  const signUp = async (email: string, password: string) => {
    try {
      const { error } = await supabase.auth.signUp({
        email,
        password,
        options: { emailRedirectTo: `${window.location.origin}/` }
      });
      return { error: error as Error | null };
    } catch (directError: any) {
      console.log('Direct signup failed, using proxy...', directError?.message);
      try {
        const { data, error: fnError } = await supabase.functions.invoke('auth-proxy', {
          body: { action: 'signup', email, password, redirectTo: `${window.location.origin}/` },
        });
        if (fnError) return { error: new Error(fnError.message) };
        if (data?.error) return { error: new Error(data.error_description || data.error || data.msg) };
        // If auto-confirm is on, data will contain access_token
        if (data?.access_token) {
          await supabase.auth.setSession({
            access_token: data.access_token,
            refresh_token: data.refresh_token,
          });
        }
        return { error: null };
      } catch (proxyError: any) {
        return { error: new Error(proxyError?.message || 'Signup failed') };
      }
    }
  };

  const signOut = async () => {
    await performSignOut();
  };

  return (
    <AuthContext.Provider value={{ user, session, loading, signIn, signUp, signOut }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
