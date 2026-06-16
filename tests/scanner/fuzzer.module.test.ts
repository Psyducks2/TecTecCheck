import { describe, it, expect, vi, beforeEach } from "vitest";
import axios from "axios";
import { FuzzerModule } from "../../src/scanner/modules/fuzzer.module";

vi.mock("axios");
const mockedAxios = vi.mocked(axios);

function mockAxiosAll(
  defaultResp: { status: number; headers?: Record<string, string>; data?: string },
  routes: Record<string, { status: number; headers?: Record<string, string>; data?: string }> = {}
) {
  mockedAxios.get = vi.fn().mockImplementation((url: string) => {
    for (const [path, resp] of Object.entries(routes)) {
      if (url.endsWith(path)) {
        return Promise.resolve({ status: resp.status, headers: resp.headers ?? {}, data: resp.data ?? "" });
      }
    }
    return Promise.resolve({ status: defaultResp.status, headers: defaultResp.headers ?? {}, data: defaultResp.data ?? "" });
  });
}

describe("FuzzerModule", () => {
  const ctx = { url: "https://example.com", scanId: "scan-001" };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("quando servidor retorna 404 para paths desconhecidos (normal)", () => {
    it("reporta finding HIGH para /admin com status 200", async () => {
      mockAxiosAll({ status: 404 }, { "/admin": { status: 200, data: "<html>admin</html>" } });
      const findings = await new FuzzerModule().execute(ctx);
      const f = findings.find((f) => f.evidence?.includes("/admin"));
      expect(f).toBeDefined();
      expect(f!.severity).toBe("HIGH");
    });

    it("reporta finding CRITICAL para /.env com status 200", async () => {
      mockAxiosAll({ status: 404 }, { "/.env": { status: 200, data: "DB_PASS=secret" } });
      const findings = await new FuzzerModule().execute(ctx);
      const f = findings.find((f) => f.evidence?.includes("/.env"));
      expect(f).toBeDefined();
      expect(f!.severity).toBe("CRITICAL");
    });

    it("não reporta findings para status 404", async () => {
      mockAxiosAll({ status: 404 });
      const findings = await new FuzzerModule().execute(ctx);
      expect(findings).toHaveLength(0);
    });

    it("reporta AUTH_REQUIRED para 401 em path não-admin como MEDIUM", async () => {
      mockAxiosAll({ status: 404 }, { "/secret": { status: 401 } });
      const findings = await new FuzzerModule().execute(ctx);
      const f = findings.find((f) => f.type === "AUTH_REQUIRED");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("MEDIUM");
    });

    it("reporta AUTH_REQUIRED para 401 em path admin como HIGH", async () => {
      mockAxiosAll({ status: 404 }, { "/admin": { status: 401 } });
      const findings = await new FuzzerModule().execute(ctx);
      const f = findings.find((f) => f.type === "AUTH_REQUIRED");
      expect(f).toBeDefined();
      expect(f!.severity).toBe("HIGH");
    });

    it("reporta REDIRECT para 301", async () => {
      mockAxiosAll({ status: 404 }, { "/admin": { status: 301, headers: { location: "/login" } } });
      const findings = await new FuzzerModule().execute(ctx);
      const f = findings.find((f) => f.type === "REDIRECT" && f.evidence?.includes("301"));
      expect(f).toBeDefined();
      expect(f!.evidence).toContain("/login");
    });

    it("reporta REDIRECT para 302", async () => {
      mockAxiosAll({ status: 404 }, { "/dashboard": { status: 302, headers: { location: "/auth" } } });
      const findings = await new FuzzerModule().execute(ctx);
      const f = findings.find((f) => f.type === "REDIRECT" && f.evidence?.includes("302"));
      expect(f).toBeDefined();
    });

    it("reporta 403 em path sensível como SENSITIVE_PATH_BLOCKED MEDIUM", async () => {
      mockAxiosAll({ status: 404 }, { "/.env": { status: 403 } });
      const findings = await new FuzzerModule().execute(ctx);
      const f = findings.find((f) => f.evidence?.includes("/.env"));
      expect(f).toBeDefined();
      expect(f!.type).toBe("SENSITIVE_PATH_BLOCKED");
      expect(f!.severity).toBe("MEDIUM");
    });

    it("reporta 403 em path genérico como EXPOSED_PATH MEDIUM", async () => {
      mockAxiosAll({ status: 404 }, { "/config.php": { status: 403 } });
      const findings = await new FuzzerModule().execute(ctx);
      const f = findings.find((f) => f.evidence?.includes("/config.php"));
      expect(f).toBeDefined();
      expect(f!.type).toBe("EXPOSED_PATH");
      expect(f!.severity).toBe("MEDIUM");
    });

    it("ignora 200 que retorna página 404 customizada", async () => {
      mockAxiosAll(
        { status: 404 },
        { "/randompath": { status: 200, data: "<html><body>404 Not Found</body></html>" } }
      );
      const findings = await new FuzzerModule().execute(ctx);
      expect(findings).toHaveLength(0);
    });
  });

  describe("quando servidor retorna 403 para tudo (WAF/genérico)", () => {
    it("ignora 403 em paths genéricos (sem flood)", async () => {
      mockAxiosAll(
        { status: 403, data: "<html>Access Denied</html>" },
        { "/config.php": { status: 403 } }
      );
      const findings = await new FuzzerModule().execute(ctx);
      const exposed = findings.filter((f) => f.type === "EXPOSED_PATH");
      expect(exposed).toHaveLength(0);
    });

    it("não gera ACCESS_DENIED_CUSTOM (tipo removido)", async () => {
      mockAxiosAll(
        { status: 403, data: "<html>Access Denied</html>" },
        { "/admin": { status: 403, data: "<html>Pagina customizada</html>" } }
      );
      const findings = await new FuzzerModule().execute(ctx);
      const custom = findings.filter((f) => f.type === "ACCESS_DENIED_CUSTOM");
      expect(custom).toHaveLength(0);
    });

    it("ainda reporta 403 em paths sensíveis como MEDIUM", async () => {
      mockAxiosAll(
        { status: 403, data: "<html>Access Denied</html>" },
        { "/.env": { status: 403 } }
      );
      const findings = await new FuzzerModule().execute(ctx);
      const sensitive = findings.filter((f) => f.type === "SENSITIVE_PATH_BLOCKED");
      expect(sensitive.length).toBeGreaterThanOrEqual(1);
      expect(sensitive.every((f) => f.severity === "MEDIUM")).toBe(true);
    });

    it("não faz fetchBody extra para 403 e ignora paths genéricos", async () => {
      const callCount = { get: 0 };
      mockedAxios.get = vi.fn().mockImplementation((url: string) => {
        callCount.get++;
        return Promise.resolve({ status: 403, headers: {}, data: "Access Denied" });
      });
      const findings = await new FuzzerModule().execute(ctx);
      expect(callCount.get).toBe(288);
      const exposed = findings.filter((f) => f.type === "EXPOSED_PATH");
      expect(exposed).toHaveLength(0);
    });

    it("ainda reporta 200 normalmente", async () => {
      mockAxiosAll(
        { status: 403, data: "<html>Access Denied</html>" },
        { "/admin": { status: 200, data: "<html>Admin Panel</html>" } }
      );
      const findings = await new FuzzerModule().execute(ctx);
      const exposed = findings.find((f) => f.type === "EXPOSED_PATH" && f.evidence?.includes("/admin"));
      expect(exposed).toBeDefined();
      expect(exposed!.severity).toBe("HIGH");
    });

    it("ainda reporta 401 normalmente", async () => {
      mockAxiosAll(
        { status: 403, data: "<html>Access Denied</html>" },
        { "/secret": { status: 401 } }
      );
      const findings = await new FuzzerModule().execute(ctx);
      const auth = findings.find((f) => f.type === "AUTH_REQUIRED");
      expect(auth).toBeDefined();
    });
  });
});
