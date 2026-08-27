// Tests for `createGitClient` — the workspace-bound entry point.
//
// The wrapping is thin: build an FsClient from `ws.provider()`
// once, hand it to `cloneWith` / `diffWith` on each call. The
// behaviour of those two is covered by clone.test.ts and
// diff.test.ts; what's worth pinning here is the binding contract.

import type { SQLiteWorkspaceProvider } from "@cloudflare/dofs";
import { describe, expect, it, vi } from "vitest";

import type { IsomorphicGitFSClient } from "./adapter.js";
import { createGitClient } from "./index.js";

// `createGitClient` only reads `.provider()` and forwards the
// result to the adapter. A stub provider is enough; the adapter
// itself is exercised by its own integration path.
const opaqueProvider = {} as unknown as SQLiteWorkspaceProvider;

function stubFs(): IsomorphicGitFSClient {
  return {
    promises: {
      readFile: vi.fn(async () => new Uint8Array()),
    },
  };
}

describe("createGitClient", () => {
  it("calls ws.provider() lazily on first use, then caches the FsClient", async () => {
    const provider = vi.fn(() => opaqueProvider);
    const fs = stubFs();
    const adapter = vi.fn(async () => fs);

    const client = createGitClient({ adapter })({ ws: { provider } });

    // No work happens at construction time.
    expect(provider).not.toHaveBeenCalled();
    expect(adapter).not.toHaveBeenCalled();

    // First op fails (the fake fs/git layer below isomorphic-git
    // can't service a real clone) — but provider/adapter are
    // observed before the failure.
    await client.clone({ url: "https://example.test/repo.git" }).catch(() => {});
    expect(provider).toHaveBeenCalledTimes(1);
    expect(adapter).toHaveBeenCalledTimes(1);
    expect(adapter).toHaveBeenCalledWith(opaqueProvider);

    // A second op reuses the cached FsClient — neither provider
    // nor adapter is invoked again.
    await client.diff().catch(() => {});
    expect(provider).toHaveBeenCalledTimes(1);
    expect(adapter).toHaveBeenCalledTimes(1);
  });

  it("refuses a denied remote before touching the workspace", async () => {
    const provider = vi.fn(() => opaqueProvider);
    const adapter = vi.fn(async () => stubFs());
    const client = createGitClient({ adapter })({ ws: { provider } });

    await expect(client.clone({ url: "https://169.254.169.254/r.git" })).rejects.toThrow(
      /private or local address/,
    );
    await expect(client.push({ url: "http://example.test/r.git" })).rejects.toThrow(
      /insecure transport/,
    );
    // The check runs ahead of the adapter, so no filesystem or
    // network work happens for a refused destination.
    expect(provider).not.toHaveBeenCalled();
    expect(adapter).not.toHaveBeenCalled();
  });

  it("resolves a named remote and applies the policy to its stored URL", async () => {
    const client = createGitClient({ adapter: async () => stubFs() })({
      ws: { provider: () => opaqueProvider },
    });
    // `git remote add` on a repository created before the policy
    // existed, or through any other writer, must not become a
    // bypass: the URL behind the name is what gets checked.
    client.remoteList = async () => [{ name: "evil", url: "https://127.0.0.1/r.git" }];

    await expect(client.fetch({ remote: "evil" })).rejects.toThrow(/private or local address/);
    await expect(client.push({ remote: "evil" })).rejects.toThrow(/private or local address/);
    await expect(client.pull({ remote: "evil" })).rejects.toThrow(/private or local address/);
  });

  it("honours a widened policy", async () => {
    const client = createGitClient({
      adapter: async () => stubFs(),
      remotePolicy: { allowPrivateHosts: true },
    })({ ws: { provider: () => opaqueProvider } });

    // Past the policy, so it fails inside isomorphic-git instead.
    await expect(client.clone({ url: "https://127.0.0.1/r.git" })).rejects.not.toThrow(
      /private or local address/,
    );
  });
});
