// Tests for the remote-URL policy that gates every network git
// operation.
//
// The interesting cases are the ones an untrusted caller would
// reach for: a scheme the client can technically speak but should
// not (`http://`), a host that resolves inside the operator's own
// network (loopback, RFC 1918, `169.254.0.0/16`), and the spellings
// that hide such a host from a naive string check (IPv6 literals,
// IPv4-mapped addresses).

import { describe, expect, it } from "vitest";

import { checkGitRemoteUrl, isPrivateHost, networkGitSubcommand } from "./remote-policy.js";

function reason(url: string, policy?: Parameters<typeof checkGitRemoteUrl>[1]): string {
  const verdict = checkGitRemoteUrl(url, policy);
  if (verdict.allowed) throw new Error(`expected ${url} to be refused`);
  return verdict.reason;
}

describe("checkGitRemoteUrl", () => {
  it("allows public https remotes", () => {
    for (const url of [
      "https://github.com/example/repo.git",
      "https://example.test/r.git",
      "https://sub.example.test:8443/r.git",
    ]) {
      expect(checkGitRemoteUrl(url), url).toEqual({ allowed: true });
    }
  });

  it("allows file:// whatever the policy says — nothing leaves the workspace", () => {
    expect(checkGitRemoteUrl("file:///workspace/other.git")).toEqual({ allowed: true });
    expect(
      checkGitRemoteUrl("file:///workspace/other.git", { allowedHosts: ["github.com"] }),
    ).toEqual({ allowed: true });
  });

  it("refuses http:// by default and accepts it only when allowed", () => {
    expect(reason("http://example.test/r.git")).toContain("insecure transport");
    expect(
      checkGitRemoteUrl("http://example.test/r.git", { allowInsecureTransport: true }),
    ).toEqual({ allowed: true });
  });

  it("refuses transports the client cannot speak", () => {
    for (const url of [
      "ssh://git@example.test/r.git",
      "git://example.test/r.git",
      "git@example.test:r.git",
      "not a url",
    ]) {
      expect(reason(url), url).toContain("unsupported transport");
    }
  });

  it("refuses loopback, private, link-local, and metadata hosts", () => {
    for (const host of [
      "localhost",
      "app.localhost",
      "service.internal",
      "db.local",
      "127.0.0.1",
      "127.1.2.3",
      "0.0.0.0",
      "10.1.2.3",
      "172.16.0.1",
      "172.31.255.255",
      "192.168.1.1",
      "100.64.0.1",
      "169.254.169.254",
      "[::1]",
      "[::ffff:169.254.169.254]",
      "[fd00::1]",
      "[fe80::1]",
    ]) {
      expect(reason(`https://${host}/r.git`), host).toContain("private or local address");
    }
  });

  it("accepts a private host once the policy allows it", () => {
    expect(checkGitRemoteUrl("https://127.0.0.1/r.git", { allowPrivateHosts: true })).toEqual({
      allowed: true,
    });
  });

  it("does not mistake public addresses for private ones", () => {
    for (const host of ["8.8.8.8", "172.32.0.1", "192.169.1.1", "99.1.2.3", "[2606:4700::1111]"]) {
      expect(checkGitRemoteUrl(`https://${host}/r.git`), host).toEqual({ allowed: true });
    }
  });

  it("enforces allowedHosts, including a subdomain wildcard", () => {
    const policy = { allowedHosts: ["github.com", "*.githubusercontent.com"] };
    expect(checkGitRemoteUrl("https://github.com/e/r.git", policy)).toEqual({ allowed: true });
    expect(checkGitRemoteUrl("https://raw.githubusercontent.com/e/r", policy)).toEqual({
      allowed: true,
    });
    // The wildcard covers subdomains, not the bare domain, and a
    // lookalike suffix is not a match.
    expect(reason("https://githubusercontent.com/e/r", policy)).toContain("not in the allowed");
    expect(reason("https://evil-github.com/e/r.git", policy)).toContain("not in the allowed");
  });

  it("an empty allowedHosts list refuses every network remote", () => {
    expect(reason("https://github.com/e/r.git", { allowedHosts: [] })).toContain(
      "not in the allowed",
    );
  });

  it("matches hosts case-insensitively", () => {
    const policy = { allowedHosts: ["github.com"] };
    expect(checkGitRemoteUrl("https://GitHub.COM/e/r.git", policy)).toEqual({ allowed: true });
    expect(reason("https://LocalHost/r.git")).toContain("private or local address");
  });
});

describe("isPrivateHost", () => {
  it("judges an IPv4-mapped IPv6 address on its v4 octets", () => {
    expect(isPrivateHost("::ffff:10.0.0.1")).toBe(true);
    expect(isPrivateHost("::ffff:8.8.8.8")).toBe(false);
  });
});

describe("networkGitSubcommand", () => {
  it("names the network subcommands and nothing else", () => {
    expect(networkGitSubcommand(["clone", "https://example.test/r.git"])).toBe("clone");
    expect(networkGitSubcommand(["fetch"])).toBe("fetch");
    expect(networkGitSubcommand(["pull"])).toBe("pull");
    expect(networkGitSubcommand(["push"])).toBe("push");
    expect(networkGitSubcommand(["status"])).toBeUndefined();
    expect(networkGitSubcommand([])).toBeUndefined();
  });

  it("looks past the global -C option in both spellings", () => {
    expect(networkGitSubcommand(["-C", "/repo", "push"])).toBe("push");
    expect(networkGitSubcommand(["-C/repo", "fetch"])).toBe("fetch");
    expect(networkGitSubcommand(["-C", "/repo", "log"])).toBeUndefined();
  });
});
