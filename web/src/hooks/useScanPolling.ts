import { useState, useCallback, useRef, useEffect } from "react";
import { postScan, getReport } from "../api";
import type { ScanConfig, ScanReport } from "../types";

const TERMINAL = new Set(["COMPLETED", "FAILED"]);
const POLL_MS = 1500;

export function useScanPolling() {
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const generation = useRef(0);

  const stop = useCallback(() => {
    // Invalidate any in-flight poll loop and clear a pending timer.
    generation.current += 1;
    if (timer.current) clearTimeout(timer.current);
    timer.current = null;
    setBusy(false);
  }, []);

  // Cancel polling when the component unmounts.
  useEffect(() => stop, [stop]);

  const start = useCallback(
    async (url: string, config?: ScanConfig) => {
      stop();
      const myGen = generation.current;
      const isCurrent = () => generation.current === myGen;

      setError(null);
      setReport(null);
      setBusy(true);

      const poll = async (scanId: string) => {
        try {
          const next = await getReport(scanId);
          if (!isCurrent()) return;
          setReport(next);
          if (TERMINAL.has(next.status)) {
            setBusy(false);
            return;
          }
          timer.current = setTimeout(() => poll(scanId), POLL_MS);
        } catch (err) {
          if (!isCurrent()) return;
          setError(err instanceof Error ? err.message : "Erro ao buscar relatório");
          setBusy(false);
        }
      };

      try {
        const { scanId } = await postScan(url, config);
        if (!isCurrent()) return;
        await poll(scanId);
      } catch (err) {
        if (!isCurrent()) return;
        setError(err instanceof Error ? err.message : "Erro ao iniciar scan");
        setBusy(false);
      }
    },
    [stop]
  );

  return { report, error, busy, start };
}
