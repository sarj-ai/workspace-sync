import { z } from "zod";

import { sha256Hex } from "../operations/canonical.ts";
import {
  defineOperation,
  type RegisteredOperation,
} from "../operations/registry.ts";
import { JsonValueSchema } from "../operations/schemas.ts";
import type { GoogleIdentityAttestationRecovery } from "./google-identity-attestation-recovery.ts";

const ACTION = "google-identity-attempt:resolve-observation";
const DigestSchema = z.string().regex(/^[a-f0-9]{64}$/u);
const DetailsSchema = z.strictObject({
  attemptId: DigestSchema,
  sourceHash: DigestSchema,
  target: z.enum(["before", "after"]),
});
export function createGoogleIdentityAttestationRecoveryOperation(
  recovery: Pick<GoogleIdentityAttestationRecovery, "read" | "settle">,
): RegisteredOperation {
  return defineOperation({
    name: "workspace-directory.github-identity-attempt-recovery",
    policyVersion: "2026-09-26.1",
    inputSchema: z.strictObject({}),
    detailsSchema: DetailsSchema,
    actionIds: [ACTION],
    ttlSeconds: 600,
    metadata: {
      destructive: false,
      execution: "sync",
      requiredRole: "operations-admin",
      requiredScope: "workspace-directory:apply",
      risk: "high",
      sourceSystems: ["google-workspace", "workspace-directory-ledger"],
      targetSystems: ["workspace-directory-ledger"],
      summary:
        "Resolve one attempted Google identity write using exact fresh before/after evidence; never repeat the write.",
      supportsApply: true,
      supportsPlan: true,
    },
    async buildPlan() {
      const snapshot = await recovery.read();
      return {
        applicable: true,
        diagnostics: [],
        sourceFingerprints: fingerprints(snapshot.sourceHash),
        changes: snapshot.resolved
          ? []
          : [
              {
                actionId: ACTION,
                before: { resolution: "unresolved" },
                after: {
                  resolution:
                    snapshot.target === "before"
                      ? "observed-before"
                      : "observed-after",
                },
                kind: "change",
                risk: "high",
                details: DetailsSchema.parse(snapshotDetails(snapshot)),
                confirmationCounts: { incidentResolutions: 1 },
                display:
                  "Resolve one historical Google identity write from exact provider observation",
                reason:
                  "Preserve the original attempt; an observed-before outcome requires a distinct newly reviewed mapping plan.",
                resource: {
                  type: "google-workspace.identity-attempt",
                  id: requiredId(snapshot.attemptId),
                },
              },
            ],
      };
    },
    async readSourceFingerprints() {
      const snapshot = await recovery.read();
      return fingerprints(snapshot.sourceHash);
    },
    async readManagedSlice(change) {
      const snapshot = await recovery.read();
      if (
        snapshot.sourceHash !== change.details.sourceHash ||
        snapshot.attemptId !== change.details.attemptId ||
        snapshot.target !== change.details.target
      )
        throw new Error("google_identity_attempt_recovery_conflict");
      if (!snapshot.resolved) return { resolution: "unresolved" };
      return {
        resolution:
          snapshot.target === "before" ? "observed-before" : "observed-after",
      };
    },
    async applyChange(change) {
      await recovery.settle({
        ...change.details,
        changeHash: await sha256Hex(JsonValueSchema.parse(change)),
      });
    },
  });
}
function fingerprints(version: string) {
  return [
    {
      authority: "workspace-directory-ledger",
      resourceType: "google-identity-attestation-attempt",
      resourceId: "latest",
      version,
    },
  ];
}
function requiredId(value: null | string) {
  if (value === null) throw new Error("google_identity_attempt_missing");
  return value;
}
function snapshotDetails(snapshot: {
  attemptId: null | string;
  sourceHash: string;
  target: null | string;
}) {
  return {
    attemptId: requiredId(snapshot.attemptId),
    sourceHash: snapshot.sourceHash,
    target: snapshot.target,
  };
}
