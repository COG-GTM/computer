// Remote access policy for network git operations.
//
// Network git can contact arbitrary hosts when its URL, authentication
// callback, or HTTP transport is forwarded without validation. This module
// applies a deny-by-default host and scheme policy to destinations, guards
// authentication callbacks from redirects, and checks the final URL reported
// by the redirect-following HTTP transport.

import { RemoteNotAllowedError } from "./errors.js";

/** Controls which remote URLs network git may contact. */
export interface GitRemoteAccessPolicy {
  /** Exact hosts, host-and-port entries, or `*.` subdomain patterns. */
  allowedHosts?: readonly string[];
  /** Also allow `http://` remotes when set. */
  allowInsecureHttp?: boolean;
}

interface HttpRequestArgs {
  url: string;
}

interface HttpResponse {
  url?: string;
}

interface HttpTransport {
  request(args: HttpRequestArgs): Promise<HttpResponse>;
}

/**
 * Parse and validate a remote URL against the configured access policy.
 *
 * Userinfo remains valid for credentialed remotes; only hostname and port
 * participate in the allowlist match.
 */
export function assertRemoteAllowed(
  rawUrl: string,
  policy: GitRemoteAccessPolicy | undefined,
): URL {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch (cause) {
    throw new RemoteNotAllowedError(rawUrl, "URL could not be parsed", { cause });
  }

  const allowedHosts = policy?.allowedHosts?.filter((pattern) => pattern.trim() !== "") ?? [];
  if (allowedHosts.length === 0) {
    const noPolicyMessage =
      "network git is disabled: no allowed remote hosts are configured. " +
      "Pass remoteAccess.allowedHosts to createGitClient().";
    throw new RemoteNotAllowedError(undefined, noPolicyMessage);
  }

  const protocolAllowed =
    url.protocol === "https:" || (url.protocol === "http:" && policy?.allowInsecureHttp);
  if (!protocolAllowed) {
    throw new RemoteNotAllowedError(rawUrl, `scheme '${url.protocol.slice(0, -1)}' is not allowed`);
  }

  const hostname = url.hostname.toLowerCase();
  const port = url.port || (url.protocol === "https:" ? "443" : "80");
  if (!allowedHosts.some((pattern) => matchesHostPattern(hostname, port, pattern))) {
    throw new RemoteNotAllowedError(
      rawUrl,
      `host '${hostname}${url.port ? `:${url.port}` : ""}' is not in the allowed-hosts policy`,
    );
  }

  return url;
}

/**
 * Guard an authentication callback so redirects cannot solicit credentials
 * for a host outside the configured policy.
 */
export function guardAuthCallback<Auth, Result>(
  onAuth: ((url: string, auth: Auth) => Result) | undefined,
  policy: GitRemoteAccessPolicy | undefined,
): ((url: string, auth: Auth) => Result | undefined) | undefined {
  if (onAuth === undefined) return undefined;
  return (url, auth) => {
    try {
      assertRemoteAllowed(url, policy);
    } catch (cause) {
      if (cause instanceof RemoteNotAllowedError) return undefined;
      throw cause;
    }
    return onAuth(url, auth);
  };
}

/**
 * Guard each HTTP request and the final URL reported after redirects.
 *
 * The underlying transport follows redirects itself, so the response URL is
 * the only seam where a cross-host redirect is observable. Failing there
 * stops the packfile POST that would follow an info/refs redirect.
 */
export function guardHttpTransport(
  http: object,
  policy: GitRemoteAccessPolicy | undefined,
): object {
  const transport = http as HttpTransport;
  return {
    request: async (args: HttpRequestArgs) => {
      assertRemoteAllowed(args.url, policy);
      const response = await transport.request(args);
      if (response.url !== undefined) {
        assertRemoteAllowed(response.url, policy);
      }
      return response;
    },
  };
}

function matchesHostPattern(hostname: string, port: string, rawPattern: string): boolean {
  const pattern = rawPattern.trim().toLowerCase();
  if (pattern === "*" || (pattern.includes("*") && !pattern.startsWith("*."))) return false;

  const separator = pattern.lastIndexOf(":");
  const hasPort = separator > -1 && /^\d+$/.test(pattern.slice(separator + 1));
  const expectedPort = hasPort ? pattern.slice(separator + 1) : undefined;
  const expectedHost = hasPort ? pattern.slice(0, separator) : pattern;
  if (expectedHost === "" || (expectedPort !== undefined && expectedPort === "")) return false;
  if (expectedPort !== undefined && expectedPort !== port) return false;

  if (expectedHost.startsWith("*.")) {
    const suffix = expectedHost.slice(2);
    return suffix !== "" && hostname.endsWith(`.${suffix}`) && hostname !== suffix;
  }
  return expectedHost === hostname;
}
