import { createHash } from "node:crypto";

import { Database, initializeSchema } from "@cloudflare/dofs";
import { SQLiteTestStorage } from "@cloudflare/dofs/testing";
import { describe, expect, it } from "vitest";

import { BlobIntake, hex, MAX_BLOB_BYTES } from "./blob-intake.js";

function digest(bytes: Uint8Array): Uint8Array {
  const hash = createHash("sha256");
  hash.update(bytes);
  return new Uint8Array(hash.digest());
}

function makeDatabase(): { db: Database; close: () => void } {
  const storage = new SQLiteTestStorage();
  const db = new Database(storage);
  initializeSchema(db, () => 1000);
  return { db, close: () => storage.close() };
}

describe("BlobIntake", () => {
  it("stages a requested blob and tracks its bytes", () => {
    const { db, close } = makeDatabase();
    try {
      const bytes = new TextEncoder().encode("hello");
      const hash = digest(bytes);
      const intake = new BlobIntake({ requested: [hash] });

      intake.stage(db, hash, bytes, 1000);

      expect(intake.totalBytes).toBe(bytes.byteLength);
      expect(db.scalar<number>("SELECT COUNT(*) FROM vfs_blobs")).toBe(1);
      expect(db.scalar<number>("SELECT COUNT(*) FROM vfs_blob_bytes")).toBe(1);
    } finally {
      close();
    }
  });

  it("rejects an oversized blob before staging it", () => {
    const { db, close } = makeDatabase();
    try {
      const bytes = new Uint8Array(MAX_BLOB_BYTES + 1);
      const hash = digest(bytes);
      const intake = new BlobIntake();

      expect(() => intake.stage(db, hash, bytes, 1000)).toThrow(
        `blob ${hex(hash)} exceeds maximum size`,
      );
      expect(db.scalar<number>("SELECT COUNT(*) FROM vfs_blobs")).toBe(0);
    } finally {
      close();
    }
  });

  it("rejects a blob that was not requested", () => {
    const { db, close } = makeDatabase();
    try {
      const bytes = new TextEncoder().encode("hello");
      const hash = digest(bytes);
      const requested = digest(new TextEncoder().encode("other"));
      const intake = new BlobIntake({ requested: [requested] });

      expect(() => intake.stage(db, hash, bytes, 1000)).toThrow(
        `blob ${hex(hash)} was not requested`,
      );
    } finally {
      close();
    }
  });

  it("rejects a duplicate hash within one intake", () => {
    const { db, close } = makeDatabase();
    try {
      const bytes = new TextEncoder().encode("hello");
      const hash = digest(bytes);
      const intake = new BlobIntake();

      intake.stage(db, hash, bytes, 1000);

      expect(() => intake.stage(db, hash, bytes, 1000)).toThrow(
        `blob ${hex(hash)} was already staged`,
      );
    } finally {
      close();
    }
  });

  it("rejects a blob that exceeds the intake byte budget", () => {
    const { db, close } = makeDatabase();
    try {
      const bytes = new TextEncoder().encode("hello");
      const hash = digest(bytes);
      const intake = new BlobIntake({ maxTotalBytes: bytes.byteLength - 1 });

      expect(() => intake.stage(db, hash, bytes, 1000)).toThrow(
        `blob ${hex(hash)} exceeds the intake byte budget`,
      );
    } finally {
      close();
    }
  });

  it("rejects bytes whose content does not match the hash", () => {
    const { db, close } = makeDatabase();
    try {
      const bytes = new TextEncoder().encode("hello");
      const hash = digest(new TextEncoder().encode("other"));
      const intake = new BlobIntake();

      expect(() => intake.stage(db, hash, bytes, 1000)).toThrow(
        `blob ${hex(hash)} does not match its content hash`,
      );
      expect(db.scalar<number>("SELECT COUNT(*) FROM vfs_blobs")).toBe(0);
    } finally {
      close();
    }
  });
});
