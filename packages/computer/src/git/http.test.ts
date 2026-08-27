import { describe, expect, it, vi } from "vitest";

import type { WorkspaceEgressPolicy } from "../runtime/egress.js";
import { GitError } from "./errors.js";
import { createEgressHttp, type GitHttpTransport } from "./http.js";

async function* bodyChunks(...chunks: Uint8Array[]): AsyncIterableIterator<Uint8Array> {
  yield* chunks;
}

describe("createEgressHttp", () => {
  it('blocks requests when the egress mode is "none"', async () => {
    const loadDirect = vi.fn(async () => ({ request: vi.fn() }));
    const http = (await createEgressHttp({ mode: "none" }, loadDirect)) as GitHttpTransport;

    await expect(
      http.request({
        url: "https://example.test/repo.git",
      }),
    ).rejects.toMatchObject({
      code: "EEGRESSBLOCKED",
      message:
        'git network access is disabled by the workspace egress policy (mode "none")',
    });
    expect(loadDirect).not.toHaveBeenCalled();
  });

  it("forwards requests through an HTTP gateway and maps the response", async () => {
    let capturedRequest: Request | undefined;
    const gateway = {
      fetch: vi.fn(async (request: Request) => {
        capturedRequest = request;
        return new Response(new Uint8Array([4, 5, 6]), {
          status: 206,
          statusText: "Partial Content",
          headers: { "content-type": "application/octet-stream" },
        });
      }),
    };
    const policy = {
      mode: "http-gateway",
      gateway,
    } as unknown as WorkspaceEgressPolicy;
    const http = (await createEgressHttp(policy, vi.fn())) as GitHttpTransport;

    const response = await http.request({
      url: "http://internal.test/repo.git",
      method: "POST",
      headers: { Authorization: "Bearer token" },
      body: bodyChunks(new Uint8Array([1, 2]), new Uint8Array([3])),
    });

    expect(capturedRequest).toBeInstanceOf(Request);
    expect(capturedRequest?.url).toBe("http://internal.test/repo.git");
    expect(capturedRequest?.method).toBe("POST");
    expect(capturedRequest?.headers.get("authorization")).toBe("Bearer token");
    expect(capturedRequest?.redirect).toBe("manual");
    expect(new Uint8Array(await capturedRequest!.arrayBuffer())).toEqual(new Uint8Array([1, 2, 3]));
    expect(response.statusCode).toBe(206);
    expect(response.statusMessage).toBe("Partial Content");
    expect(Object.getPrototypeOf(response.headers)).toBeNull();
    expect(response.headers).toEqual(
      expect.objectContaining({ "content-type": "application/octet-stream" }),
    );

    const responseBytes: Uint8Array[] = [];
    for await (const chunk of response.body) responseBytes.push(chunk);
    expect(responseBytes).toEqual([new Uint8Array([4, 5, 6])]);
  });

  it('loads the direct transport when the egress mode is "direct"', async () => {
    const direct = { request: vi.fn() };
    const loadDirect = vi.fn(async () => direct);

    await expect(createEgressHttp({ mode: "direct" }, loadDirect)).resolves.toBe(direct);
    expect(loadDirect).toHaveBeenCalledTimes(1);
  });

  it("uses GitError for blocked requests", async () => {
    const http = (await createEgressHttp({ mode: "none" }, vi.fn())) as GitHttpTransport;

    try {
      await http.request({ url: "https://example.test/repo.git" });
    } catch (cause) {
      expect(cause).toBeInstanceOf(GitError);
      return;
    }
    throw new Error("expected the request to reject");
  });
});
