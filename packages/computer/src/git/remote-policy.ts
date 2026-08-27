// Policy for the remote URLs the git surface is willing to talk to.
//
// Network git subcommands (`clone`, `fetch`, `pull`, `push`) run
// wherever the git client lives, which for the worker-shell
// backend is the host durable object rather than the sandbox
// Dynamic Worker. The sandbox's `globalOutbound` therefore never
// sees those requests, so scheme checking alone lets a sandboxed
// agent reach any host the durable object can reach — internal
// services, cloud metadata endpoints, or an attacker's collector.
//
// This module is the shared gate. It is deliberately dependency
// free so both the host-side git client and the shell-side `git`
// command can import it without pulling isomorphic-git into a
// bundle.

/** Subcommands that make the git client talk to a remote. */
export const NETWORK_GIT_SUBCOMMANDS = ["clone", "fetch", "pull", "push"] as const;

export type NetworkGitSubcommand = (typeof NETWORK_GIT_SUBCOMMANDS)[number];

/**
 * Restrictions applied to every remote URL a network git
 * operation is asked to contact.
 *
 * The defaults are the strict ones: `https://` (plus `file://`,
 * which never leaves the workspace) and no private, loopback, or
 * link-local destination. Operators widen the policy explicitly
 * when they need to.
 */
export interface GitRemotePolicy {
  /**
   * Allow plain `http://` remotes. Off by default: the request
   * leaves the durable object unencrypted, and http is the usual
   * shape of an internal-service probe.
   */
  allowInsecureTransport?: boolean;
  /**
   * Allow hosts that name the local machine or a private network
   * (loopback, `169.254.0.0/16`, RFC 1918, carrier-grade NAT,
   * `localhost`, `*.internal`, and friends). Off by default. Turn
   * it on for a local test remote.
   */
  allowPrivateHosts?: boolean;
  /**
   * When set, the remote host must appear in this list. Entries
   * are host names compared case-insensitively; a leading `*.`
   * matches subdomains but not the bare domain. An empty list
   * rejects every network remote.
   */
  allowedHosts?: readonly string[];
}

export type RemoteUrlVerdict = { allowed: true } | { allowed: false; reason: string };

/** Host names that always name the local machine or a private network. */
const PRIVATE_HOST_SUFFIXES = [".localhost", ".local", ".internal", ".home.arpa", ".localdomain"];

const PRIVATE_HOST_NAMES = ["localhost", "localhost.localdomain"];

/**
 * Decide whether a network git operation may contact `url`.
 *
 * `file://` URLs are accepted whatever the policy says: they read
 * from the workspace itself, so there is no request to confine.
 */
export function checkGitRemoteUrl(url: string, policy: GitRemotePolicy = {}): RemoteUrlVerdict {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return {
      allowed: false,
      reason: `unsupported transport for '${url}'. Only https:// and file:// are supported.`,
    };
  }
  if (parsed.protocol === "file:") return { allowed: true };
  const insecure = parsed.protocol === "http:";
  if (parsed.protocol !== "https:" && !insecure) {
    return {
      allowed: false,
      reason: `unsupported transport for '${url}'. Only https:// and file:// are supported.`,
    };
  }
  if (insecure && policy.allowInsecureTransport !== true) {
    return {
      allowed: false,
      reason: `refusing to use insecure transport for '${url}'. Use https://, or allow http:// in the git remote policy.`,
    };
  }
  const host = parsed.hostname.toLowerCase();
  if (host === "") {
    return { allowed: false, reason: `remote URL '${url}' has no host.` };
  }
  if (policy.allowPrivateHosts !== true && isPrivateHost(host)) {
    return {
      allowed: false,
      reason: `remote host '${host}' names a private or local address. Sandboxed git may only reach public remotes.`,
    };
  }
  if (policy.allowedHosts !== undefined && !isAllowedHost(host, policy.allowedHosts)) {
    return {
      allowed: false,
      reason: `remote host '${host}' is not in the allowed git remote hosts.`,
    };
  }
  return { allowed: true };
}

/**
 * True when `host` names the local machine, a private network, or
 * a link-local address — including the cloud metadata endpoints
 * that live on `169.254.0.0/16`.
 */
export function isPrivateHost(host: string): boolean {
  const name = host.toLowerCase();
  if (PRIVATE_HOST_NAMES.includes(name)) return true;
  if (PRIVATE_HOST_SUFFIXES.some((suffix) => name.endsWith(suffix))) return true;
  // URL.hostname keeps the brackets around an IPv6 literal and
  // normalizes the address, so match on the colon and unwrap.
  if (name.includes(":")) return isPrivateIpv6(name);
  const octets = parseIpv4(name);
  if (octets !== undefined) return isPrivateIpv4(octets);
  return false;
}

function parseIpv4(host: string): [number, number, number, number] | undefined {
  const parts = host.split(".");
  if (parts.length !== 4) return undefined;
  const octets: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return undefined;
    const value = Number(part);
    if (value > 255) return undefined;
    octets.push(value);
  }
  return [octets[0], octets[1], octets[2], octets[3]];
}

function isPrivateIpv4(octets: [number, number, number, number]): boolean {
  const [a, b] = octets;
  if (a === 0) return true; // 0.0.0.0/8, "this network"
  if (a === 10) return true; // RFC 1918
  if (a === 127) return true; // loopback
  if (a === 100 && b >= 64 && b <= 127) return true; // carrier-grade NAT
  if (a === 169 && b === 254) return true; // link-local, incl. metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // RFC 1918
  if (a === 192 && b === 168) return true; // RFC 1918
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
  if (a >= 224) return true; // multicast and reserved
  return false;
}

function isPrivateIpv6(host: string): boolean {
  const name = host.replace(/^\[|\]$/g, "");
  if (name === "::" || name === "::1") return true;
  // An IPv4-mapped or IPv4-compatible address hides a v4 literal
  // in its last field; judge it on the v4 rules.
  const lastField = name.slice(name.lastIndexOf(":") + 1);
  const mapped = parseIpv4(lastField);
  if (mapped !== undefined) return isPrivateIpv4(mapped);
  const first = name.split(":")[0];
  if (first === "") return true; // any other `::`-prefixed address
  const leading = Number.parseInt(first, 16);
  if (Number.isNaN(leading)) return false;
  if ((leading & 0xfe00) === 0xfc00) return true; // unique local, fc00::/7
  if ((leading & 0xffc0) === 0xfe80) return true; // link-local, fe80::/10
  return false;
}

function isAllowedHost(host: string, allowed: readonly string[]): boolean {
  return allowed.some((entry) => {
    const pattern = entry.trim().toLowerCase();
    if (pattern === "") return false;
    if (pattern.startsWith("*.")) return host.endsWith(pattern.slice(1));
    return host === pattern;
  });
}

/**
 * Name of the network subcommand in `argv`, or undefined when the
 * command touches nothing but the local workspace.
 *
 * Leading global options are skipped so `git -C /repo clone ...`
 * is recognized as a clone. Only `-C` exists today; an unknown
 * global option ends the scan and the argv is treated as local,
 * because the dispatcher rejects it before any network happens.
 */
export function networkGitSubcommand(argv: readonly string[]): NetworkGitSubcommand | undefined {
  let index = 0;
  while (index < argv.length) {
    const token = argv[index];
    if (token === "-C") {
      index += 2;
      continue;
    }
    if (token.startsWith("-C") && token.length > 2) {
      index += 1;
      continue;
    }
    break;
  }
  const sub = argv[index];
  if (sub === undefined) return undefined;
  return (NETWORK_GIT_SUBCOMMANDS as readonly string[]).includes(sub)
    ? (sub as NetworkGitSubcommand)
    : undefined;
}
