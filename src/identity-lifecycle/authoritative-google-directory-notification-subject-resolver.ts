import { z } from "zod";

import { normalizeIdentityEmail } from "../identity-sync/normalize-identity-email.ts";
import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import type {
  GoogleDirectoryLifecycleNotification,
  GoogleDirectoryUserId,
  GoogleDirectoryWatchUserBody,
} from "./contracts.ts";
import { GoogleDirectoryUserIdSchema } from "./contracts.ts";
import type { GoogleDirectoryNotificationSubjectResolver } from "./webhook-handler.ts";

export interface GoogleDirectoryLifecycleSubjectClient {
  getUserById(
    googleUserId: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<GoogleDirectoryUser | null>;
  listDeletedUsers(
    runId: string,
    deadlineAt?: number,
  ): Promise<GoogleDirectoryUser[]>;
}

const RESOLUTION_DEADLINE_MS = 20_000;
const DeletionTimeSchema = z.iso.datetime({ offset: true });

function sameIdentity(
  user: GoogleDirectoryUser,
  subject: GoogleDirectoryWatchUserBody,
): boolean {
  return (
    user.id === subject.id &&
    normalizeIdentityEmail(user.primaryEmail) ===
      normalizeIdentityEmail(subject.primaryEmail)
  );
}

export class AuthoritativeGoogleDirectoryNotificationSubjectResolver implements GoogleDirectoryNotificationSubjectResolver {
  readonly #client: GoogleDirectoryLifecycleSubjectClient;
  readonly #clock: () => number;

  constructor(
    client: GoogleDirectoryLifecycleSubjectClient,
    clock: () => number = Date.now,
  ) {
    this.#client = client;
    this.#clock = clock;
  }

  async resolveImmutableGoogleUserId(
    notification: GoogleDirectoryLifecycleNotification,
    subject: GoogleDirectoryWatchUserBody,
  ): Promise<GoogleDirectoryUserId | null> {
    const runId = crypto.randomUUID();
    const deadlineAt = this.#clock() + RESOLUTION_DEADLINE_MS;
    const active = await this.#client.getUserById(
      subject.id,
      runId,
      deadlineAt,
    );
    if (active !== null)
      return sameIdentity(active, subject)
        ? GoogleDirectoryUserIdSchema.parse(active.id)
        : null;
    if (notification.event !== "delete") return null;
    const deletedUsers = await this.#client.listDeletedUsers(runId, deadlineAt);
    const matches = deletedUsers.filter(
      (candidate) => candidate.id === subject.id,
    );
    const deleted = matches.length === 1 ? matches[0] : undefined;
    return deleted !== undefined &&
      DeletionTimeSchema.safeParse(deleted.deletionTime).success &&
      sameIdentity(deleted, subject)
      ? GoogleDirectoryUserIdSchema.parse(deleted.id)
      : null;
  }
}
