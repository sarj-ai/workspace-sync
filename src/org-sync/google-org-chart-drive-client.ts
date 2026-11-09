import { z } from "zod";

import { normalizeIdentityEmail } from "../identity-sync/normalize-identity-email.ts";
import {
  type ResourceLeaseRepository,
  resourceLeaseKey,
  withResourceLease,
} from "../identity-sync/resource-lease.ts";
import { sha256 } from "../runtime/sha256.ts";
import { logEvent } from "../shared/log-event.ts";
import { orgSyncSettings } from "./config.ts";
import { exchangeGoogleToken } from "./exchange-google-token.ts";
import { fetchWithRetry, type RetryOptions } from "./http.ts";

const DRIVE_SCOPE = "https://www.googleapis.com/auth/drive";
const DRIVE_FILES_ENDPOINT = "https://www.googleapis.com/drive/v3/files";
// Drive v3 removed File.etag. Keep this narrow v2 seam so APPLY retains an atomic provider precondition.
const DRIVE_V2_FILES_ENDPOINT = "https://www.googleapis.com/drive/v2/files";
const DRIVE_V2_UPLOAD_ENDPOINT =
  "https://www.googleapis.com/upload/drive/v2/files";
const EXPECTED_NAME = "Organization Chart";
const LEGACY_NAME = "Sarj Organization Chart.html";
const EXPECTED_MIME_TYPE = "text/html";
const PERMISSIONS_PAGE_LIMIT = 100;
const PERMISSIONS_PAGE_SIZE = 100;
const MAX_MUTATION_RUN_MS = 120_000;
const WRITE_READBACK_HEADROOM_MS = 30_000;
const LEASE_POST_DEADLINE_FENCE_MS = 30_000;

const FileSchema = z.object({
  driveId: z.string().min(1),
  id: z.string().min(1),
  mimeType: z.string().min(1),
  name: z.string().min(1),
  parents: z.array(z.string()).default([]),
  trashed: z.boolean().default(false),
  webViewLink: z.url().optional(),
});
const DriveV2FileEtagSchema = z.object({
  etag: z.string().min(1),
  id: z.string().min(1),
});
const PermissionsSchema = z.object({
  nextPageToken: z.string().min(1).optional(),
  permissions: z.array(
    z.object({
      deleted: z.boolean().optional().default(false),
      domain: z.string().optional(),
      emailAddress: z.string().optional(),
      id: z.string().min(1),
      permissionDetails: z
        .array(z.object({ inheritedFrom: z.string().optional() }))
        .default([]),
      role: z.string().min(1),
      type: z.enum(["anyone", "domain", "group", "user"]),
    }),
  ),
});

export interface OrgChartDriveResult {
  action: "unchanged" | "updated";
  fileId: string;
  webViewLink: string;
}

export interface GoogleOrgChartDriveClientOptions extends Pick<
  RetryOptions,
  "fetchImpl" | "random" | "sleep"
> {
  driveId: string;
  fileId: string;
  leaseRepository?: ResourceLeaseRepository | undefined;
  privateKey: string;
  serviceAccountEmail: string;
  userProject: string;
}

export interface GoogleOrgChartDriveUpsertRequest {
  deadlineAt?: number;
  expectedCurrentSha256: string;
  expectedFileId?: string | undefined;
  html: string;
  runId: string;
}

export interface OrgChartDriveClient {
  readonly fileId: string;
  readContentSha256(runId: string, deadlineAt?: number): Promise<string>;
  upsert(
    request: GoogleOrgChartDriveUpsertRequest,
  ): Promise<OrgChartDriveResult>;
}

export class GoogleOrgChartDriveClient implements OrgChartDriveClient {
  readonly #options: GoogleOrgChartDriveClientOptions;
  #token: { expiresAt: number; value: string } | null = null;

  constructor(options: GoogleOrgChartDriveClientOptions) {
    this.#options = Object.freeze({ ...options });
  }

  get fileId(): string {
    return this.#options.fileId;
  }

  async upsert(
    request: GoogleOrgChartDriveUpsertRequest,
  ): Promise<OrgChartDriveResult> {
    if (
      request.expectedFileId !== undefined &&
      request.expectedFileId !== this.fileId
    )
      throw new Error("org_chart_artifact_identity_changed");
    const repository = this.#options.leaseRepository;
    if (repository === undefined)
      throw new Error("org_chart_artifact_lease_required");
    const deadlineAt = Math.min(
      request.deadlineAt ?? Infinity,
      Date.now() + MAX_MUTATION_RUN_MS,
    );
    const key = resourceLeaseKey(
      `google-drive/artifact/${await sha256(this.#options.fileId)}`,
    );
    const durationMs = deadlineAt - Date.now() + LEASE_POST_DEADLINE_FENCE_MS;
    if (deadlineAt <= Date.now())
      throw new Error("org_chart_artifact_deadline_exceeded");
    const execution = await withResourceLease(
      repository,
      key,
      durationMs,
      async (lease) =>
        this.#upsertUnderLease({ ...request, deadlineAt }, async () => {
          const remainingMs = deadlineAt - Date.now();
          if (remainingMs < WRITE_READBACK_HEADROOM_MS)
            throw new Error("org_chart_artifact_write_headroom_exhausted");
          await repository.assertActive(
            lease,
            remainingMs + LEASE_POST_DEADLINE_FENCE_MS,
          );
        }),
    );
    if (execution.kind === "busy")
      throw new Error("org_chart_artifact_lease_busy");
    return execution.result;
  }

  async readContentSha256(runId: string, deadlineAt?: number): Promise<string> {
    const token = await this.#accessToken(runId, deadlineAt);
    const file = await this.#getMetadata(token, runId, deadlineAt);
    this.#validateDestination(file);
    await this.#validatePermissions(token, runId, deadlineAt);
    return sha256(await this.#download(token, runId, deadlineAt));
  }

  async #upsertUnderLease(
    request: GoogleOrgChartDriveUpsertRequest,
    assertWriteAuthority: () => Promise<void>,
  ): Promise<OrgChartDriveResult> {
    const { deadlineAt, expectedCurrentSha256, html, runId } = request;
    const token = await this.#accessToken(runId, deadlineAt);
    const file = await this.#getMetadata(token, runId, deadlineAt);
    this.#validateDestination(file);
    await this.#validatePermissions(token, runId, deadlineAt);
    const current = await this.#download(token, runId, deadlineAt);
    if ((await sha256(current)) !== expectedCurrentSha256) {
      throw new Error("Managed Google Drive org chart changed after planning");
    }
    let changed = false;
    if (current !== html) {
      const etag = await this.#getDriveV2Etag(token, runId, deadlineAt);
      const pinnedCurrent = await this.#download(token, runId, deadlineAt);
      if ((await sha256(pinnedCurrent)) !== expectedCurrentSha256) {
        throw new Error(
          "Managed Google Drive org chart changed while binding its ETag",
        );
      }
      await assertWriteAuthority();
      await this.#update(token, html, etag, runId, deadlineAt);
      await this.#verify(token, html, runId, deadlineAt);
      changed = true;
    }
    return this.#result(changed ? "updated" : "unchanged", file);
  }

  async #accessToken(runId: string, deadlineAt?: number): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    if (this.#token && this.#token.expiresAt - 60 > now)
      return this.#token.value;
    this.#token = await exchangeGoogleToken(
      this.#options,
      DRIVE_SCOPE,
      this.#retry("google.drive.oauth", runId, deadlineAt),
    );
    return this.#token.value;
  }

  async #download(
    token: string,
    runId: string,
    deadlineAt?: number,
  ): Promise<string> {
    const query = new URLSearchParams({
      alt: "media",
      supportsAllDrives: "true",
    });
    const response = await fetchWithRetry(
      `${DRIVE_FILES_ENDPOINT}/${encodeURIComponent(this.#options.fileId)}?${query.toString()}`,
      { headers: this.#headers(token) },
      this.#retry("google.drive.files.download", runId, deadlineAt),
    );
    if (!response.ok)
      throw new Error(
        `Google Drive files.download HTTP ${String(response.status)}`,
      );
    return response.text();
  }

  async #getMetadata(
    token: string,
    runId: string,
    deadlineAt?: number,
  ): Promise<z.output<typeof FileSchema>> {
    const query = new URLSearchParams({
      fields: "driveId,id,mimeType,name,parents,trashed,webViewLink",
      supportsAllDrives: "true",
    });
    const response = await fetchWithRetry(
      `${DRIVE_FILES_ENDPOINT}/${encodeURIComponent(this.#options.fileId)}?${query.toString()}`,
      { headers: this.#headers(token) },
      this.#retry("google.drive.files.get", runId, deadlineAt),
    );
    if (!response.ok) {
      throw new Error(
        `Pinned Google Drive org chart unavailable (HTTP ${String(response.status)})`,
      );
    }
    return FileSchema.parse(await response.json());
  }

  async #getDriveV2Etag(
    token: string,
    runId: string,
    deadlineAt?: number,
  ): Promise<string> {
    const query = new URLSearchParams({
      fields: "etag,id",
      supportsAllDrives: "true",
    });
    const response = await fetchWithRetry(
      `${DRIVE_V2_FILES_ENDPOINT}/${encodeURIComponent(this.#options.fileId)}?${query.toString()}`,
      { headers: this.#headers(token) },
      this.#retry("google.drive.v2.files.get", runId, deadlineAt),
    );
    if (!response.ok) {
      throw new Error(
        `Pinned Google Drive org chart version unavailable (HTTP ${String(response.status)})`,
      );
    }
    const parsed = DriveV2FileEtagSchema.safeParse(await response.json());
    if (!parsed.success) {
      throw new Error(
        "Pinned Google Drive org chart version response omitted a valid ETag",
      );
    }
    const versioned = parsed.data;
    if (versioned.id !== this.#options.fileId) {
      throw new Error("Google Drive returned an unexpected versioned file");
    }
    return versioned.etag;
  }

  #headers(token: string): Record<string, string> {
    return {
      authorization: `Bearer ${token}`,
      "x-goog-user-project": this.#options.userProject,
    };
  }

  #result(
    action: OrgChartDriveResult["action"],
    file: z.output<typeof FileSchema>,
  ): OrgChartDriveResult {
    return {
      action,
      fileId: file.id,
      webViewLink:
        file.webViewLink ??
        `https://drive.google.com/file/d/${encodeURIComponent(file.id)}/view`,
    };
  }

  #retry(
    label: string,
    runId: string,
    deadlineAt?: number,
    maxAttempts = 3,
  ): RetryOptions {
    return {
      fetchImpl: this.#options.fetchImpl,
      label,
      ...(!(deadlineAt === undefined) && { deadlineAt }),
      maxAttempts,
      random: this.#options.random,
      runId,
      sleep: this.#options.sleep,
    };
  }

  async #update(
    token: string,
    html: string,
    expectedEtag: string,
    runId: string,
    deadlineAt?: number,
  ): Promise<void> {
    const query = new URLSearchParams({
      supportsAllDrives: "true",
      uploadType: "media",
    });
    const response = await fetchWithRetry(
      `${DRIVE_V2_UPLOAD_ENDPOINT}/${encodeURIComponent(this.#options.fileId)}?${query.toString()}`,
      {
        body: html,
        headers: {
          ...this.#headers(token),
          "content-type": EXPECTED_MIME_TYPE,
          "if-match": expectedEtag,
        },
        method: "PUT",
      },
      this.#retry("google.drive.v2.files.update", runId, deadlineAt, 1),
    );
    if (response.status === 412)
      throw new Error("Managed Google Drive org chart ETag changed");
    if (!response.ok)
      throw new Error(
        `Google Drive files.update HTTP ${String(response.status)}`,
      );
    await response.body?.cancel();
  }

  #validateDestination(file: z.output<typeof FileSchema>): void {
    if (file.id !== this.#options.fileId)
      throw new Error("Google Drive returned an unexpected file");
    if (file.trashed)
      throw new Error("Managed Google Drive org chart is trashed");
    if (file.name !== EXPECTED_NAME && file.name !== LEGACY_NAME) {
      throw new Error("Managed Google Drive org chart was renamed");
    }
    if (file.mimeType !== EXPECTED_MIME_TYPE) {
      throw new Error(
        "Managed Google Drive org chart has an unexpected MIME type",
      );
    }
    if (file.driveId !== this.#options.driveId) {
      throw new Error(
        "Managed Google Drive org chart was moved out of the All Team Shared Drive",
      );
    }
    const visibleParentsDoNotIdentifySharedDriveRoot =
      file.parents.length > 0 &&
      (file.parents.length !== 1 || file.parents[0] !== file.driveId);
    if (visibleParentsDoNotIdentifySharedDriveRoot) {
      throw new Error(
        "Managed Google Drive org chart was moved from the Shared Drive root",
      );
    }
  }

  async #validatePermissions(
    token: string,
    runId: string,
    deadlineAt?: number,
  ): Promise<void> {
    const permissions: z.output<typeof PermissionsSchema>["permissions"] = [];
    const seenPageTokens = new Set<string>();
    let pageToken: string | undefined;
    for (let page = 0; page < PERMISSIONS_PAGE_LIMIT; page += 1) {
      const query = new URLSearchParams({
        fields:
          "nextPageToken,permissions(id,type,role,emailAddress,domain,deleted,permissionDetails(inheritedFrom))",
        pageSize: String(PERMISSIONS_PAGE_SIZE),
        supportsAllDrives: "true",
      });
      if (pageToken !== undefined) query.set("pageToken", pageToken);
      // eslint-disable-next-line no-await-in-loop -- Google Drive permission pages must be validated in cursor order.
      const response = await fetchWithRetry(
        `${DRIVE_FILES_ENDPOINT}/${encodeURIComponent(this.#options.fileId)}/permissions?${query.toString()}`,
        { headers: this.#headers(token) },
        this.#retry("google.drive.permissions.list", runId, deadlineAt),
      );
      if (!response.ok) {
        throw new Error(
          `Pinned Google Drive org chart permissions unavailable (HTTP ${String(response.status)})`,
        );
      }
      // eslint-disable-next-line no-await-in-loop -- The current page determines whether another request is safe.
      const parsed = PermissionsSchema.parse(await response.json());
      permissions.push(...parsed.permissions);
      if (parsed.nextPageToken === undefined) {
        validatePermissionSet(permissions, this.#options.serviceAccountEmail);
        return;
      }
      if (seenPageTokens.has(parsed.nextPageToken)) {
        throw new Error(
          "Google Drive permissions pagination returned a repeated page token",
        );
      }
      seenPageTokens.add(parsed.nextPageToken);
      pageToken = parsed.nextPageToken;
    }
    throw new Error(
      `Google Drive permissions exceeded the ${String(PERMISSIONS_PAGE_LIMIT)} page safety limit`,
    );
  }

  async #verify(
    token: string,
    html: string,
    runId: string,
    deadlineAt?: number,
  ): Promise<void> {
    if ((await this.#download(token, runId, deadlineAt)) !== html) {
      throw new Error("Google Drive org chart read-back mismatch");
    }
    logEvent("org_chart.drive_verified", {
      bytes: new TextEncoder().encode(html).byteLength,
      "file_id": this.#options.fileId,
      "run_id": runId,
    });
  }
}

function validatePermissionSet(
  permissions: z.output<typeof PermissionsSchema>["permissions"],
  serviceAccountEmail: string,
): void {
  let serviceAccountWriterFound = false;
  for (const permission of permissions) {
    if (
      !permission.deleted &&
      validatePermission(permission, serviceAccountEmail)
    ) {
      serviceAccountWriterFound = true;
    }
  }
  if (!serviceAccountWriterFound) {
    throw new Error(
      "Managed Google Drive org chart service-account writer permission is missing",
    );
  }
}

function validatePermission(
  permission: z.output<typeof PermissionsSchema>["permissions"][number],
  serviceAccountEmail: string,
): boolean {
  if (permission.type === "anyone") {
    throw new Error("Managed Google Drive org chart has a public permission");
  }
  if (
    permission.type === "domain" &&
    permission.domain !== orgSyncSettings().managedDomain
  ) {
    throw new Error(
      "Managed Google Drive org chart has an external-domain permission",
    );
  }
  if (permission.type !== "user" && permission.type !== "group") return false;
  return validatePrincipal(permission, serviceAccountEmail);
}

function validatePrincipal(
  permission: z.output<typeof PermissionsSchema>["permissions"][number],
  serviceAccountEmail: string,
): boolean {
  const email = permission.emailAddress
    ? normalizeIdentityEmail(permission.emailAddress)
    : undefined;
  if (!email)
    throw new Error(
      "Managed Google Drive org chart has an unverifiable principal",
    );
  if (email !== normalizeIdentityEmail(serviceAccountEmail)) {
    if (!email.endsWith(`@${orgSyncSettings().managedDomain}`)) {
      throw new Error(
        "Managed Google Drive org chart has an external principal",
      );
    }
    return false;
  }
  if (permission.role !== "writer") {
    throw new Error(
      "Managed Google Drive org chart service account is not a writer",
    );
  }
  return true;
}
