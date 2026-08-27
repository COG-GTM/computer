import type { WorkspaceEgressPolicy } from "../runtime/egress.js";
import { GitError } from "./errors.js";

export interface GitHttpRequest {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: AsyncIterableIterator<Uint8Array>;
  signal?: AbortSignal;
}

export interface GitHttpResponse {
  url: string;
  method?: string;
  statusCode: number;
  statusMessage: string;
  headers: Record<string, string>;
  body: AsyncIterable<Uint8Array>;
}

export interface GitHttpTransport {
  request(request: GitHttpRequest): Promise<GitHttpResponse>;
}

export async function createEgressHttp(
  policy: WorkspaceEgressPolicy,
  loadDirect: () => Promise<object>,
): Promise<object> {
  switch (policy.mode) {
    case "none":
      return {
        request(): Promise<GitHttpResponse> {
          return Promise.reject(
            new GitError(
              "EEGRESSBLOCKED",
              'git network access is disabled by the workspace egress policy (mode "none")',
            ),
          );
        },
      } satisfies GitHttpTransport;
    case "direct":
      return await loadDirect();
    case "http-gateway":
      return {
        async request(request: GitHttpRequest): Promise<GitHttpResponse> {
          const body = request.body ? await collectBody(request.body) : undefined;
          const response = await policy.gateway.fetch(
            new Request(request.url, {
              method: request.method,
              headers: request.headers,
              body: body as BodyInit | undefined,
              redirect: "manual",
              signal: request.signal,
            }),
          );
          const headers: Record<string, string> = Object.create(null);
          response.headers.forEach((value, key) => {
            headers[key] = value;
          });
          return {
            url: response.url || request.url,
            method: request.method,
            statusCode: response.status,
            statusMessage: response.statusText,
            headers,
            body: responseBody(response),
          };
        },
      } satisfies GitHttpTransport;
  }
}

async function collectBody(body: AsyncIterableIterator<Uint8Array>): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  let byteLength = 0;
  for await (const chunk of body) {
    chunks.push(chunk);
    byteLength += chunk.byteLength;
  }
  const result = new Uint8Array(byteLength);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

async function* responseBody(response: Response): AsyncIterable<Uint8Array> {
  yield new Uint8Array(await response.arrayBuffer());
}
