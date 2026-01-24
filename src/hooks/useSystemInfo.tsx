import { useState, useEffect, useCallback } from 'react';

interface BatteryStatus {
  charging: boolean;
  level: number;
  chargingTime: number | null;
  dischargingTime: number | null;
}

interface NetworkInfo {
  type: string;
  effectiveType: string;
  downlink: number;
  rtt: number;
  online: boolean;
}

interface MemoryInfo {
  deviceMemory: number;
  usedJSHeapSize: number | null;
  totalJSHeapSize: number | null;
  jsHeapSizeLimit: number | null;
}

interface PerformanceInfo {
  pageLoadTime: number;
  domContentLoaded: number;
  firstPaint: number | null;
  firstContentfulPaint: number | null;
  resources: number;
  transferSize: number;
}

interface SystemInfo {
  // Device Info
  cpuCores: number;
  platform: string;
  userAgent: string;
  language: string;
  cookiesEnabled: boolean;
  doNotTrack: boolean;
  
  // Screen Info
  screenWidth: number;
  screenHeight: number;
  colorDepth: number;
  pixelRatio: number;
  
  // Battery
  battery: BatteryStatus | null;
  
  // Network
  network: NetworkInfo;
  
  // Memory
  memory: MemoryInfo;
  
  // Performance
  performance: PerformanceInfo;
  
  // Timing
  timestamp: Date;
  uptime: number;
}

export const useSystemInfo = (refreshInterval = 2000) => {
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [startTime] = useState(Date.now());

  const getPerformanceInfo = useCallback((): PerformanceInfo => {
    const perf = window.performance;
    const navigation = perf.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
    const paintEntries = perf.getEntriesByType('paint');
    const resources = perf.getEntriesByType('resource') as PerformanceResourceTiming[];
    
    const firstPaint = paintEntries.find(e => e.name === 'first-paint');
    const firstContentfulPaint = paintEntries.find(e => e.name === 'first-contentful-paint');
    
    const totalTransferSize = resources.reduce((acc, r) => acc + (r.transferSize || 0), 0);

    return {
      pageLoadTime: navigation ? Math.round(navigation.loadEventEnd - navigation.startTime) : 0,
      domContentLoaded: navigation ? Math.round(navigation.domContentLoadedEventEnd - navigation.startTime) : 0,
      firstPaint: firstPaint ? Math.round(firstPaint.startTime) : null,
      firstContentfulPaint: firstContentfulPaint ? Math.round(firstContentfulPaint.startTime) : null,
      resources: resources.length,
      transferSize: totalTransferSize,
    };
  }, []);

  const getNetworkInfo = useCallback((): NetworkInfo => {
    const connection = (navigator as any).connection || 
                       (navigator as any).mozConnection || 
                       (navigator as any).webkitConnection;

    if (connection) {
      return {
        type: connection.type || 'unknown',
        effectiveType: connection.effectiveType || 'unknown',
        downlink: connection.downlink || 0,
        rtt: connection.rtt || 0,
        online: navigator.onLine,
      };
    }

    return {
      type: 'unknown',
      effectiveType: 'unknown',
      downlink: 0,
      rtt: 0,
      online: navigator.onLine,
    };
  }, []);

  const getMemoryInfo = useCallback((): MemoryInfo => {
    const memory = (performance as any).memory;
    
    return {
      deviceMemory: (navigator as any).deviceMemory || 0,
      usedJSHeapSize: memory?.usedJSHeapSize || null,
      totalJSHeapSize: memory?.totalJSHeapSize || null,
      jsHeapSizeLimit: memory?.jsHeapSizeLimit || null,
    };
  }, []);

  const updateSystemInfo = useCallback(async () => {
    try {
      // Get battery info
      let batteryStatus: BatteryStatus | null = null;
      if ('getBattery' in navigator) {
        try {
          const battery = await (navigator as any).getBattery();
          batteryStatus = {
            charging: battery.charging,
            level: Math.round(battery.level * 100),
            chargingTime: battery.chargingTime === Infinity ? null : battery.chargingTime,
            dischargingTime: battery.dischargingTime === Infinity ? null : battery.dischargingTime,
          };
        } catch (e) {
          console.log('Battery API not available');
        }
      }

      const info: SystemInfo = {
        // Device Info
        cpuCores: navigator.hardwareConcurrency || 0,
        platform: navigator.platform || 'unknown',
        userAgent: navigator.userAgent,
        language: navigator.language,
        cookiesEnabled: navigator.cookieEnabled,
        doNotTrack: navigator.doNotTrack === '1',
        
        // Screen Info
        screenWidth: window.screen.width,
        screenHeight: window.screen.height,
        colorDepth: window.screen.colorDepth,
        pixelRatio: window.devicePixelRatio,
        
        // Battery
        battery: batteryStatus,
        
        // Network
        network: getNetworkInfo(),
        
        // Memory
        memory: getMemoryInfo(),
        
        // Performance
        performance: getPerformanceInfo(),
        
        // Timing
        timestamp: new Date(),
        uptime: Math.floor((Date.now() - startTime) / 1000),
      };

      setSystemInfo(info);
      setIsLoading(false);
    } catch (error) {
      console.error('Error getting system info:', error);
      setIsLoading(false);
    }
  }, [getNetworkInfo, getMemoryInfo, getPerformanceInfo, startTime]);

  useEffect(() => {
    updateSystemInfo();
    const interval = setInterval(updateSystemInfo, refreshInterval);
    
    // Listen for online/offline events
    const handleOnline = () => updateSystemInfo();
    const handleOffline = () => updateSystemInfo();
    
    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      clearInterval(interval);
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, [updateSystemInfo, refreshInterval]);

  return { systemInfo, isLoading, refresh: updateSystemInfo };
};

export type { SystemInfo, BatteryStatus, NetworkInfo, MemoryInfo, PerformanceInfo };
