import { z } from "zod";

import type { GoogleDirectoryUser } from "../org-sync/model.ts";
import { GoogleDirectoryUserIdSchema } from "./contracts.ts";

const GoogleDirectoryDeletionTimeSchema = z.iso.datetime({ offset: true });

/**
 * Read-only Google Directory surface used to resolve one immutable user ID.
 *
 * Implementations must return `null` from `getUserById` only when Google
 * Directory returns 404. Authentication, transport, rate-limit, and other
 * provider failures must reject so they cannot be mistaken for deletion.
 */
export interface GoogleDirectoryAuthoritySourcePort {
  getUserById(
    googleUserId: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<GoogleDirectoryUser | null>;
  listDeletedAuthorityUsers(
    runId: string,
    deadlineAt?: number,
  ): Promise<GoogleDirectoryUser[]>;
}

// eslint-disable-next-line @sarj/require-port-for-service, @sarj/require-interface-for-exported-class -- Callers use this concrete boundary; a second public interface would be unused duplication.
export class GoogleDirectoryAuthorityReader {
  readonly #directory: GoogleDirectoryAuthoritySourcePort;

  constructor(directory: GoogleDirectoryAuthoritySourcePort) {
    this.#directory = directory;
  }

  /*
   * Resolves the current authoritative record for an exact immutable Google
   * user ID. A live lookup is always attempted first. Only its 404 (`null`)
   * result permits a complete deleted-user inventory lookup.
   */
  async getUserById(
    googleUserId: string,
    correlationId: string,
    deadlineAt?: number,
  ): Promise<GoogleDirectoryUser | null> {
    const immutableGoogleUserId =
      GoogleDirectoryUserIdSchema.parse(googleUserId);
    const live = await this.#directory.getUserById(
      immutableGoogleUserId,
      correlationId,
      deadlineAt,
    );
    if (live !== null) {
      assertExactImmutableId(live, immutableGoogleUserId);
      return live;
    }

    const deletedUsers = await this.#directory.listDeletedAuthorityUsers(
      correlationId,
      deadlineAt,
    );
    const deletedMatches = deletedUsers.filter(
      (candidate) => candidate.id === immutableGoogleUserId,
    );
    if (deletedMatches.length > 1) {
      throw new Error("google_directory_authority_duplicate_deleted_user");
    }
    const deleted = deletedMatches[0];
    if (deleted === undefined) return null;
    if (
      !GoogleDirectoryDeletionTimeSchema.safeParse(deleted.deletionTime).success
    ) {
      throw new Error(
        "google_directory_authority_deleted_user_deletion_time_invalid",
      );
    }
    return deleted;
  }
}

function assertExactImmutableId(
  user: GoogleDirectoryUser,
  googleUserId: string,
): void {
  if (user.id !== googleUserId) {
    throw new Error("google_directory_authority_user_id_mismatch");
  }
}
