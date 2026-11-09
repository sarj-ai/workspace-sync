import { logEvent } from "../shared/log-event.ts";
import type {
  GoogleOrgChartDriveClient,
  OrgChartDriveResult,
} from "./google-org-chart-drive-client.ts";
import type { GoogleDirectoryUser } from "./model.ts";
import { type OrgChartPolicy, orgChartParticipants } from "./org-chart.ts";
import { renderOrgChartHtml } from "./render-org-chart-html.ts";

const MAX_RUN_MS = 2 * 60 * 1000;

export interface OrgChartRunReport {
  bytes: number;
  currentSha256: string;
  drive: null | OrgChartDriveResult;
  fileId: string;
  mode: "audit" | "live";
  people: number;
  photos: number;
  runId: string;
  sha256: string;
}

export interface IOrgChartService {
  run(request: OrgChartRunRequest): Promise<OrgChartRunReport>;
}

export type OrgChartDrivePort = Pick<
  GoogleOrgChartDriveClient,
  "fileId" | "readContentSha256" | "upsert"
>;

export type OrgChartRunRequest =
  | {
      expectedCurrentSha256: string;
      expectedFileId?: string | undefined;
      expectedSha256: string;
      mode: "live";
      users: readonly GoogleDirectoryUser[];
    }
  | { mode: "audit"; users: readonly GoogleDirectoryUser[] };

export class OrgChartService implements IOrgChartService {
  readonly #drive: OrgChartDrivePort;
  readonly #policy: OrgChartPolicy;

  constructor(drive: OrgChartDrivePort, policy: OrgChartPolicy) {
    this.#drive = drive;
    this.#policy = policy;
  }

  async run(request: OrgChartRunRequest): Promise<OrgChartRunReport> {
    const { mode, users } = request;
    const runId = crypto.randomUUID();
    const deadlineAt = Date.now() + MAX_RUN_MS;
    orgChartParticipants(users, this.#policy);
    // Directory photo bytes are not canonical across Google edge responses. Embedding them made
    // identical Workspace authority produce different signed plans, so the managed artifact uses
    // deterministic initials. The renderer still supports explicit photos for non-managed callers.
    const { html, people, photos } = renderOrgChartHtml(
      [...users],
      this.#policy,
    );
    const encoded = new TextEncoder().encode(html);
    const digest = new Uint8Array(
      await crypto.subtle.digest("SHA-256", encoded),
    );
    const sha256 = [...digest]
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
    if (mode === "live" && sha256 !== request.expectedSha256) {
      throw new Error("Organization chart source changed after planning");
    }
    const drive =
      mode === "live"
        ? await this.#drive.upsert({
            deadlineAt,
            expectedCurrentSha256: request.expectedCurrentSha256,
            expectedFileId: request.expectedFileId,
            html,
            runId,
          })
        : null;
    const currentSha256 =
      mode === "live"
        ? sha256
        : await this.#drive.readContentSha256(runId, deadlineAt);
    logEvent("org_chart.run_completed", {
      action: drive?.action ?? "audit",
      bytes: encoded.byteLength,
      people,
      photos,
      "run_id": runId,
      sha256,
    });
    return {
      bytes: encoded.byteLength,
      currentSha256,
      drive,
      fileId: this.#drive.fileId,
      mode,
      people,
      photos,
      runId,
      sha256,
    };
  }
}
