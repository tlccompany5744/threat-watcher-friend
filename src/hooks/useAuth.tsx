import { createContext, useContext, useEffect, useState, useRef, useCallback, ReactNode } from 'react';
import { User, Session } from '@supabase/supabase-js';
import { supabase } from '@/integrations/supabase/client';
import { toast } from '@/hooks/use-toast';

const SESSION_TIMEOUT_MS = 30 * 60 * 1000;
const WARNING_BEFORE_MS = 2 * 60 * 1000;

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
    // Try direct auth first
    try {
      const result = await supabase.auth.signInWithPassword({ email, password });
      if (!result.error) return { error: null };
      // If it's not a network error, return the auth error directly
      if (!result.error.message?.includes('fetch')) {
        return { error: result.error as Error };
      }
      // Fall through to proxy for network errors
      console.log('Direct auth returned network error, trying proxy...');
    } catch (directError: any) {
      console.log('Direct auth threw exception, trying proxy...', directError?.message);
    }

    // Fallback: use the auth-proxy edge function via supabase.functions.invoke
    try {
      const { data, error: invokeError } = await supabase.functions.invoke('auth-proxy', {
        body: { action: 'login', email, password },
      });
      if (invokeError) return { error: new Error(invokeError.message || 'Authentication failed') };
      if (data?.error || data?.msg === 'Invalid login credentials') {
        return { error: new Error(data.error_description || data.msg || data.error || 'Invalid credentials') };
      }
      if (data?.access_token) {
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
  };

  const signUp = async (email: string, password: string) => {
    try {
      const result = await supabase.auth.signUp({
        email,
        password,
        options: { emailRedirectTo: `${window.location.origin}/` }
      });
      if (!result.error) return { error: null };
      if (!result.error.message?.includes('fetch')) {
        return { error: result.error as Error };
      }
      console.log('Direct signup returned network error, trying proxy...');
    } catch (directError: any) {
      console.log('Direct signup threw exception, trying proxy...', directError?.message);
    }

    // Fallback: use the auth-proxy edge function via supabase.functions.invoke
    try {
      const { data, error: invokeError } = await supabase.functions.invoke('auth-proxy', {
        body: { action: 'signup', email, password, redirectTo: `${window.location.origin}/` },
      });
      if (invokeError) return { error: new Error(invokeError.message || 'Signup failed') };
      if (data?.error) return { error: new Error(data.error_description || data.error || data.msg) };
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
