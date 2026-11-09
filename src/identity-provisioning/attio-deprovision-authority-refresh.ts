import {
  AttioDeprovisionAuthorityCaptureError,
  AttioDeprovisionAuthoritySchema,
} from "./attio-deprovision-authority-capture.ts";
import {
  ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_SCHEMA_VERSION,
  type AttioDeprovisionAuthoritySnapshotStorePort,
} from "./attio-deprovision-authority-snapshot-store.ts";
import { GitHubDeprovisionGoogleAuthorityInventorySchema } from "./github-deprovision-google-authority-contract.ts";

export interface AttioDeprovisionAuthorityRefreshPorts {
  captureAttio(): Promise<unknown>;
  captureGoogle(): Promise<unknown>;
  store: AttioDeprovisionAuthoritySnapshotStorePort;
}

export type AttioDeprovisionAuthorityRefreshErrorComponent =
  | "attio-capture"
  | "google-capture";
export type AttioDeprovisionAuthorityRefreshErrorCode =
  | "source-invalid"
  | "source-unavailable";

export class AttioDeprovisionAuthorityRefreshError extends Error {
  readonly code: AttioDeprovisionAuthorityRefreshErrorCode;
  readonly component: AttioDeprovisionAuthorityRefreshErrorComponent;

  constructor(options: {
    component: AttioDeprovisionAuthorityRefreshErrorComponent;
    code: AttioDeprovisionAuthorityRefreshErrorCode;
    cause?: unknown;
  }) {
    super(
      `attio_deprovision_authority_${options.component.replace("-", "_")}_${options.code.replace("-", "_")}`,
      options,
    );
    this.name = "AttioDeprovisionAuthorityRefreshError";
    this.code = options.code;
    this.component = options.component;
  }
}

export interface AttioDeprovisionAuthorityRefreshResult {
  readonly capturedAt: string;
  readonly deletedUsers: number;
  readonly scimStatus: "available" | "payment-required";
  readonly scimUsers: number;
  readonly users: number;
  readonly workspaceMembers: number;
}

/* Captures Attio first and the sole lifecycle authority last before one atomic KV replacement. */
export async function refreshAttioDeprovisionAuthoritySnapshot(
  ports: AttioDeprovisionAuthorityRefreshPorts,
): Promise<AttioDeprovisionAuthorityRefreshResult> {
  const rawAttio = await captureSource(
    () => ports.captureAttio(),
    "attio-capture",
  );
  const attio = AttioDeprovisionAuthoritySchema.safeParse(rawAttio);
  if (!attio.success) {
    throw new AttioDeprovisionAuthorityRefreshError({
      component: "attio-capture",
      code: "source-invalid",
    });
  }
  // Google is intentionally observed last because it is the sole lifecycle authority.
  // The caller supplies one shared deadline across both provider captures.
  const rawGoogle = await captureSource(
    () => ports.captureGoogle(),
    "google-capture",
  );
  const google =
    GitHubDeprovisionGoogleAuthorityInventorySchema.safeParse(rawGoogle);
  if (!google.success) {
    throw new AttioDeprovisionAuthorityRefreshError({
      component: "google-capture",
      code: "source-invalid",
    });
  }
  // Anchor freshness to the older source observation. Attio captures its timestamp only after
  // completing all Attio reads, then Google is captured last under the same deadline.
  const capturedAt = attio.data.capturedAt;
  await ports.store.write({
    attio: attio.data,
    capturedAt,
    google: google.data,
    schemaVersion: ATTIO_DEPROVISION_AUTHORITY_SNAPSHOT_SCHEMA_VERSION,
  });
  return {
    capturedAt,
    deletedUsers: google.data.deletedUsers.length,
    scimStatus: attio.data.scimStatus,
    scimUsers: attio.data.scimUsers.length,
    users: google.data.users.length,
    workspaceMembers: attio.data.workspaceMembers.length,
  };
}

async function captureSource(
  capture: () => Promise<unknown>,
  component: AttioDeprovisionAuthorityRefreshErrorComponent,
): Promise<unknown> {
  try {
    return await capture();
  } catch (error) {
    if (error instanceof AttioDeprovisionAuthorityCaptureError) throw error;
    throw new AttioDeprovisionAuthorityRefreshError({
      component,
      code: "source-unavailable",
      cause: error,
    });
  }
}
