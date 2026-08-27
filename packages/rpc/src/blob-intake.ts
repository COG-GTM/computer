// Guarded intake for blob bytes that arrive from a sync peer.
//
// `stageBlob` trusts its caller to have checked that the bytes hash to
// the key they land under. Bytes off the wire come from the other end
// of the sync session, which the receiver does not control, so the
// receiver checks them here before they reach storage: one intake per
// object stream, and every object is bounded, solicited, unique and
// hash-verified before it is staged. A failure throws, which abandons
// the stream and leaves the cursor where it was.

import { createHash } from "node:crypto";

import { type Database, stageBlob } from "@cloudflare/dofs";

// 512 KiB matches the dofs CHUNK_SIZE so honest producers never emit a
// larger chunk.
export const MAX_BLOB_BYTES = 512 * 1024;

export function hex(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.byteLength; i++) s += bytes[i].toString(16).padStart(2, "0");
  return s;
}

export class BlobIntake {
  readonly #requested: Set<string> | undefined;
  readonly #staged = new Set<string>();
  readonly #maxTotalBytes: number | undefined;
  #totalBytes = 0;

  constructor(options: { requested?: Uint8Array[]; maxTotalBytes?: number } = {}) {
    this.#requested =
      options.requested === undefined ? undefined : new Set(options.requested.map(hex));
    this.#maxTotalBytes = options.maxTotalBytes;
  }

  get totalBytes(): number {
    return this.#totalBytes;
  }

  stage(db: Database, hash: Uint8Array, bytes: Uint8Array, now: number): void {
    const hashHex = hex(hash);
    if (bytes.byteLength > MAX_BLOB_BYTES) {
      throw new Error(`blob ${hashHex} exceeds maximum size of ${MAX_BLOB_BYTES} bytes`);
    }
    if (this.#requested !== undefined && !this.#requested.has(hashHex)) {
      throw new Error(`blob ${hashHex} was not requested`);
    }
    if (this.#staged.has(hashHex)) {
      throw new Error(`blob ${hashHex} was already staged`);
    }
    if (
      this.#maxTotalBytes !== undefined &&
      this.#totalBytes + bytes.byteLength > this.#maxTotalBytes
    ) {
      throw new Error(`blob ${hashHex} exceeds the intake byte budget`);
    }
    const digest = createHash("sha256");
    digest.update(bytes);
    if (hex(new Uint8Array(digest.digest())) !== hashHex) {
      throw new Error(`blob ${hashHex} does not match its content hash`);
    }
    stageBlob(db, hash, bytes, now);
    this.#staged.add(hashHex);
    this.#totalBytes += bytes.byteLength;
  }
}
