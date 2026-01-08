import { serve } from "https://deno.land/std@0.190.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface ScanRequest {
  host: string;
  startPort: number;
  endPort: number;
  scanId?: string;
}

interface PortResult {
  port: number;
  status: "open" | "closed" | "filtered";
  service?: string;
  responseTime?: number;
}

// Common port to service mapping
const commonPorts: Record<number, string> = {
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  25: "SMTP",
  53: "DNS",
  80: "HTTP",
  110: "POP3",
  143: "IMAP",
  443: "HTTPS",
  445: "SMB",
  993: "IMAPS",
  995: "POP3S",
  3306: "MySQL",
  3389: "RDP",
  5432: "PostgreSQL",
  6379: "Redis",
  8080: "HTTP-Alt",
  8443: "HTTPS-Alt",
  27017: "MongoDB",
};

// Critical ports that get retry logic for accuracy
const criticalPorts = new Set([21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443, 27017]);

// Scan configuration - tuned for accuracy like nmap -sT
const SCAN_CONFIG = {
  timeout: 2000,           // 2 seconds - allows slow services like SSH to respond
  batchSize: 50,           // Reduced concurrency to avoid rate limiting
  retryAttempts: 2,        // Retry critical ports on failure
  retryDelay: 500,         // Delay between retries
  connectionHoldTime: 100, // Hold connection briefly to ensure handshake completes
};

async function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function scanPortOnce(host: string, port: number): Promise<PortResult> {
  const startTime = Date.now();
  
  try {
    // Use Deno.connect for true TCP socket scanning (like nmap -sT)
    const conn = await Promise.race([
      Deno.connect({ hostname: host, port, transport: "tcp" }),
      new Promise<never>((_, reject) => 
        setTimeout(() => reject(new Error("TIMEOUT")), SCAN_CONFIG.timeout)
      )
    ]) as Deno.Conn;
    
    const responseTime = Date.now() - startTime;
    
    // Hold connection briefly to ensure TCP handshake completes fully
    // This is important for services like SSH that may take time to respond
    await delay(SCAN_CONFIG.connectionHoldTime);
    
    // Close the connection properly
    try {
      conn.close();
    } catch {
      // Connection may already be closed by remote
    }
    
    return {
      port,
      status: "open",
      service: commonPorts[port] || "unknown",
      responseTime,
    };
  } catch (error: any) {
    const errorMessage = error.message || "";
    
    // ECONNREFUSED = port is definitely closed (RST packet received)
    if (errorMessage.includes("refused") || 
        errorMessage.includes("ECONNREFUSED") ||
        errorMessage.includes("Connection refused")) {
      return { port, status: "closed" };
    }
    
    // Timeout = port is filtered (no response - firewall dropping packets)
    if (errorMessage.includes("TIMEOUT") || 
        errorMessage.includes("timed out") ||
        error.name === "AbortError") {
      return { port, status: "filtered" };
    }
    
    // Host unreachable or network errors
    if (errorMessage.includes("unreachable") ||
        errorMessage.includes("EHOSTUNREACH") ||
        errorMessage.includes("ENETUNREACH")) {
      return { port, status: "filtered" };
    }
    
    // Default to closed for other errors
    return { port, status: "closed" };
  }
}

async function scanPort(host: string, port: number): Promise<PortResult> {
  // First attempt
  let result = await scanPortOnce(host, port);
  
  // Retry logic for critical ports that show as closed/filtered
  // This reduces false negatives for important services
  if (criticalPorts.has(port) && result.status !== "open") {
    for (let retry = 0; retry < SCAN_CONFIG.retryAttempts; retry++) {
      await delay(SCAN_CONFIG.retryDelay);
      const retryResult = await scanPortOnce(host, port);
      
      // If any retry shows open, port is open
      if (retryResult.status === "open") {
        return retryResult;
      }
      
      // Prefer "closed" over "filtered" as it's more definitive
      if (result.status === "filtered" && retryResult.status === "closed") {
        result = retryResult;
      }
    }
  }
  
  return result;
}

serve(async (req: Request): Promise<Response> => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      throw new Error("No authorization header");
    }

    const supabase = createClient(
      Deno.env.get("SUPABASE_URL") ?? "",
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
    );

    const { host, startPort, endPort, scanId }: ScanRequest = await req.json();

    console.log(`Starting accurate port scan on ${host} from ${startPort} to ${endPort}`);
    console.log(`Config: timeout=${SCAN_CONFIG.timeout}ms, batch=${SCAN_CONFIG.batchSize}, retries=${SCAN_CONFIG.retryAttempts}`);

    // Validate inputs
    if (!host || !startPort || !endPort) {
      throw new Error("Missing required parameters");
    }

    if (startPort < 1 || endPort > 65535 || startPort > endPort) {
      throw new Error("Invalid port range");
    }

    // Increased limit for full scans - adjust based on your needs
    if (endPort - startPort > 1000) {
      throw new Error("Maximum 1000 ports per scan for rate limiting");
    }

    // Get user from token
    const token = authHeader.replace("Bearer ", "");
    const { data: userData } = await supabase.auth.getUser(token);
    
    if (!userData.user) {
      throw new Error("Invalid user");
    }

    // Create scan record if not provided
    let currentScanId = scanId;
    if (!currentScanId) {
      const { data: scanData, error: scanError } = await supabase
        .from("port_scans")
        .insert({
          user_id: userData.user.id,
          target_host: host,
          start_port: startPort,
          end_port: endPort,
          status: "running",
        })
        .select()
        .single();

      if (scanError) throw scanError;
      currentScanId = scanData.id;
    }

    // Scan ports with reduced batch size for accuracy
    const results: PortResult[] = [];

    for (let i = startPort; i <= endPort; i += SCAN_CONFIG.batchSize) {
      const batch = [];
      const batchEnd = Math.min(i + SCAN_CONFIG.batchSize, endPort + 1);
      
      for (let j = i; j < batchEnd; j++) {
        batch.push(scanPort(host, j));
      }
      
      const batchResults = await Promise.all(batch);
      results.push(...batchResults);
      
      // Update progress in database
      await supabase
        .from("port_scans")
        .update({ results: results })
        .eq("id", currentScanId);
      
      console.log(`Progress: ${results.length}/${endPort - startPort + 1} ports scanned`);
    }

    // Mark scan as completed
    await supabase
      .from("port_scans")
      .update({ 
        status: "completed", 
        results: results,
        completed_at: new Date().toISOString()
      })
      .eq("id", currentScanId);

    // Log audit event
    const openPorts = results.filter(r => r.status === "open");
    const filteredPorts = results.filter(r => r.status === "filtered");
    
    await supabase.from("security_audit_logs").insert({
      user_id: userData.user.id,
      action: "port_scan_completed",
      details: { 
        host, 
        startPort, 
        endPort, 
        openPorts: openPorts.length,
        filteredPorts: filteredPorts.length,
        closedPorts: results.length - openPorts.length - filteredPorts.length,
      },
    });

    console.log(`Scan completed: ${openPorts.length} open, ${filteredPorts.length} filtered`);
    console.log(`Open ports: ${openPorts.map(p => `${p.port}/${p.service}`).join(", ") || "none"}`);

    return new Response(JSON.stringify({ 
      success: true, 
      scanId: currentScanId,
      results 
    }), {
      status: 200,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  } catch (error: any) {
    console.error("Port scan error:", error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  }
});
