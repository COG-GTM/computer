import { describe, expect, it, vi } from "vitest";

import {
  assertRemoteAllowed,
  guardAuthCallback,
  guardHttpTransport,
  type GitRemoteAccessPolicy,
} from "./remote-policy.js";

const policy: GitRemoteAccessPolicy = {
  allowedHosts: ["github.com", "git.example.com:8443", "*.example.net"],
};

describe("assertRemoteAllowed", () => {
  it("allows exact hosts case-insensitively", () => {
    expect(assertRemoteAllowed("https://GITHUB.com/repo.git", policy).hostname).toBe("github.com");
  });

  it("matches ports exactly when a pattern includes a port", () => {
    expect(
      assertRemoteAllowed("https://git.example.com:8443/repo.git", policy),
    ).toBeInstanceOf(URL);
    expect(() =>
      assertRemoteAllowed("https://git.example.com:9443/repo.git", policy),
    ).toThrow(/host 'git\.example\.com:9443'/);
  });

  it("matches any port when a pattern omits the port", () => {
    expect(assertRemoteAllowed("https://github.com:443/repo.git", policy)).toBeInstanceOf(URL);
  });

  it("matches one or more leading labels for wildcard patterns", () => {
    expect(assertRemoteAllowed("https://a.example.net/repo.git", policy)).toBeInstanceOf(URL);
    expect(assertRemoteAllowed("https://a.b.example.net/repo.git", policy)).toBeInstanceOf(URL);
    expect(() =>
      assertRemoteAllowed("https://example.net/repo.git", policy),
    ).toThrow();
  });

  it("does not match deceptive suffixes", () => {
    for (const host of ["evil-example.com", "example.com.evil.com"]) {
      expect(() =>
        assertRemoteAllowed(`https://${host}/repo.git`, policy),
      ).toThrow();
    }
  });

  it("allows userinfo while matching only the host and port", () => {
    expect(
      assertRemoteAllowed("https://user:token@github.com/repo.git", policy).hostname,
    ).toBe("github.com");
  });

  it("rejects insecure HTTP by default and allows it when configured", () => {
    expect(() =>
      assertRemoteAllowed("http://github.com/repo.git", policy),
    ).toThrow(/scheme/);
    expect(
      assertRemoteAllowed(
        "http://github.com/repo.git",
        { ...policy, allowInsecureHttp: true },
      ),
    ).toBeInstanceOf(URL);
  });

  it("rejects unsupported schemes and unparsable URLs", () => {
    for (const rawUrl of ["file:///tmp/repo", "ssh://github.com/repo", "data:text/plain,repo"]) {
      expect(() => assertRemoteAllowed(rawUrl, policy)).toThrow();
    }
    expect(() => assertRemoteAllowed("not a URL", policy)).toThrow(/parse/);
  });

  it("denies absent, empty, and blank allowlists", () => {
    for (const currentPolicy of [
      undefined,
      {},
      { allowedHosts: [] },
      { allowedHosts: [" ", "\t"] },
      { allowedHosts: ["*"] },
    ]) {
      expect(() =>
        assertRemoteAllowed("https://github.com/repo.git", currentPolicy),
      ).toThrow(/network git is disabled|allowed-hosts policy/);
    }
  });
});

describe("guardAuthCallback", () => {
  it("does not invoke the callback for a disallowed URL", () => {
    const onAuth = vi.fn(() => ({ username: "u" }));
    const guarded = guardAuthCallback(onAuth, policy);

    expect(guarded?.("https://evil.example/repo.git", {})).toBeUndefined();
    expect(onAuth).not.toHaveBeenCalled();
  });

  it("passes through an allowed URL and callback result", () => {
    const auth = { username: "u" };
    const onAuth = vi.fn(() => auth);
    const guarded = guardAuthCallback(onAuth, policy);

    expect(guarded?.("https://github.com/repo.git", {})).toBe(auth);
    expect(onAuth).toHaveBeenCalledWith("https://github.com/repo.git", {});
  });
});

describe("guardHttpTransport", () => {
  it("rejects a disallowed request without delegating", async () => {
    const request = vi.fn(async () => ({ body: "body" }));
    const guarded = guardHttpTransport({ request }, policy);

    await expect(
      (guarded as { request(args: { url: string }): Promise<unknown> }).request({
        url: "https://evil.example/repo.git",
      }),
    ).rejects.toThrow();
    expect(request).not.toHaveBeenCalled();
  });

  it("rejects a response whose final URL is off the allowlist", async () => {
    const request = vi.fn(async () => ({
      body: "body",
      url: "https://evil.example/redirected.git",
    }));
    const guarded = guardHttpTransport({ request }, policy);

    await expect(
      (guarded as { request(args: { url: string }): Promise<unknown> }).request({
        url: "https://github.com/repo.git",
      }),
    ).rejects.toThrow();
    expect(request).toHaveBeenCalledTimes(1);
  });

  it("preserves request and response fields for allowed URLs", async () => {
    const response = {
      body: "body",
      headers: { etag: "one" },
      url: "https://github.com/final.git",
    };
    const request = vi.fn(async (args: { url: string; method: string }) => ({
      ...response,
      requestMethod: args.method,
    }));
    const guarded = guardHttpTransport({ request }, policy) as {
      request(
        args: { url: string; method: string },
      ): Promise<typeof response & { requestMethod: string }>;
    };

    await expect(
      guarded.request({ url: "https://github.com/repo.git", method: "GET" }),
    ).resolves.toEqual({ ...response, requestMethod: "GET" });
  });
});
