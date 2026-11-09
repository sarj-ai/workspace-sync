import { ZodError } from "zod";

import { readBoundedText } from "../runtime/read-bounded-text.ts";
import { logEvent } from "../shared/log-event.ts";
import type { GoogleWatchChannelAuthenticator } from "./channel-authenticator.ts";
import type {
  GoogleDirectoryLifecycleNotification,
  GoogleDirectoryUserId,
  GoogleDirectoryWatchNotification,
  GoogleDirectoryWatchUserBody,
  RefreshGoogleDirectoryUserTask,
} from "./contracts.ts";
import {
  GoogleDirectoryLifecycleNotificationSchema,
  GoogleDirectoryWatchUserBodySchema,
  googleDirectoryNotificationId,
  parseGoogleDirectoryWatchHeaders,
  RefreshGoogleDirectoryUserTaskSchema,
} from "./contracts.ts";
import type {
  GoogleWatchNotificationClaim,
  GoogleWatchNotificationLease,
  GoogleWatchNotificationReceiptStore,
} from "./d1-google-watch-notification-receipt-store.ts";

export interface GoogleDirectoryNotificationSubjectResolver {
  resolveImmutableGoogleUserId(
    notification: GoogleDirectoryLifecycleNotification,
    subject: GoogleDirectoryWatchUserBody,
  ): Promise<GoogleDirectoryUserId | null>;
}

export interface GoogleDirectoryRefreshQueue {
  send(task: RefreshGoogleDirectoryUserTask): Promise<void>;
}

export interface GoogleDirectoryLifecycleWebhookDependencies {
  readonly authenticator: GoogleWatchChannelAuthenticator;
  readonly clock?: () => number;
  readonly queue: GoogleDirectoryRefreshQueue;
  readonly receipts: GoogleWatchNotificationReceiptStore;
  readonly subjectResolver: GoogleDirectoryNotificationSubjectResolver;
}

const MAX_NOTIFICATION_BODY_BYTES = 4_096;
const INVALID_NOTIFICATION_BODY_SIZE =
  "google_directory_notification_body_too_large";

async function parseClaimedNotificationBody(
  request: Request,
  receipts: GoogleWatchNotificationReceiptStore,
  lease: GoogleWatchNotificationLease,
  nowMs: number,
): Promise<
  | { readonly kind: "invalid"; readonly response: Response }
  | { readonly kind: "parsed"; readonly subject: GoogleDirectoryWatchUserBody }
> {
  try {
    return { kind: "parsed", subject: await parseNotificationBody(request) };
  } catch (error) {
    if (!isInvalidNotificationBody(error)) throw error;
    await receipts.finish(lease, "ignored", nowMs);
    return { kind: "invalid", response: new Response(null, { status: 400 }) };
  }
}

async function parseNotificationBody(
  request: Request,
): Promise<GoogleDirectoryWatchUserBody> {
  const contentLength = request.headers.get("content-length");
  if (
    contentLength !== null &&
    Number(contentLength) > MAX_NOTIFICATION_BODY_BYTES
  ) {
    throw new Error(INVALID_NOTIFICATION_BODY_SIZE);
  }
  if (request.body === null) throw new SyntaxError("Missing notification body");
  const body = await readBoundedText(
    request,
    MAX_NOTIFICATION_BODY_BYTES,
    () => new Error(INVALID_NOTIFICATION_BODY_SIZE),
  );
  return GoogleDirectoryWatchUserBodySchema.parse(JSON.parse(body));
}

function isInvalidNotificationBody(error: unknown): boolean {
  return (
    error instanceof SyntaxError ||
    error instanceof ZodError ||
    (error instanceof Error && error.message === INVALID_NOTIFICATION_BODY_SIZE)
  );
}

async function finishFailedWithoutMasking(
  receipts: GoogleWatchNotificationReceiptStore,
  lease: Parameters<GoogleWatchNotificationReceiptStore["finish"]>[0],
  nowMs: number,
): Promise<boolean> {
  try {
    const finished = await receipts.finish(lease, "failed", nowMs);
    if (!finished) {
      logEvent("google_directory.lifecycle_receipt_lease_lost", {
        "channel_id": lease.channelId,
        "message_number": lease.messageNumber,
      });
    }
    return finished;
  } catch (error) {
    logEvent("google_directory.lifecycle_receipt_failure", {
      "channel_id": lease.channelId,
      error: error instanceof Error ? error.message : String(error),
      "message_number": lease.messageNumber,
    });
    return false;
  }
}

function existingClaimResponse(
  claim: GoogleWatchNotificationClaim,
): null | Response {
  if (claim.kind === "duplicate") {
    return new Response(null, {
      status: claim.outcome === "enqueued" ? 202 : 204,
    });
  }
  if (claim.kind === "in-flight") {
    return new Response(null, {
      headers: { "retry-after": String(claim.retryAfterSeconds) },
      status: 503,
    });
  }
  return null;
}

function parseNotificationRequest(request: Request):
  | {
      readonly kind: "accepted";
      readonly notification: GoogleDirectoryWatchNotification;
    }
  | { readonly kind: "rejected"; readonly response: Response } {
  if (request.method !== "POST") {
    return {
      kind: "rejected",
      response: new Response(null, { headers: { allow: "POST" }, status: 405 }),
    };
  }
  try {
    return {
      kind: "accepted",
      notification: parseGoogleDirectoryWatchHeaders(request.headers),
    };
  } catch (error) {
    if (error instanceof ZodError) {
      return {
        kind: "rejected",
        response: new Response(null, { status: 400 }),
      };
    }
    throw error;
  }
}

export function rejectInvalidGoogleDirectoryNotificationTransport(
  request: Request,
): null | Response {
  const transport = parseNotificationRequest(request);
  return transport.kind === "rejected" ? transport.response : null;
}

export interface GoogleDirectoryLifecycleWebhookWorkflow {
  handle(request: Request): Promise<Response>;
}

export class GoogleDirectoryLifecycleWebhookHandler implements GoogleDirectoryLifecycleWebhookWorkflow {
  readonly #clock: () => number;
  readonly #dependencies: GoogleDirectoryLifecycleWebhookDependencies;

  constructor(dependencies: GoogleDirectoryLifecycleWebhookDependencies) {
    this.#clock = dependencies.clock ?? Date.now;
    this.#dependencies = dependencies;
  }

  async handle(request: Request): Promise<Response> {
    const transport = parseNotificationRequest(request);
    if (transport.kind === "rejected") return transport.response;
    const { notification } = transport;
    const nowMs = this.#clock();
    const authentication = await this.#dependencies.authenticator.authenticate(
      notification,
      nowMs,
    );
    if (authentication.kind === "rejected")
      return new Response(null, { status: 401 });

    const claim = await this.#dependencies.receipts.claim(notification, nowMs);
    if (claim.kind !== "acquired") {
      return (
        existingClaimResponse(claim) ?? new Response(null, { status: 500 })
      );
    }
    if (notification.event === "sync") {
      await this.#dependencies.receipts.finish(claim.lease, "ignored", nowMs);
      return new Response(null, { status: 204 });
    }

    try {
      const lifecycleNotification =
        GoogleDirectoryLifecycleNotificationSchema.parse(notification);
      const body = await parseClaimedNotificationBody(
        request,
        this.#dependencies.receipts,
        claim.lease,
        nowMs,
      );
      if (body.kind === "invalid") return body.response;
      const { subject } = body;
      const googleUserId =
        await this.#dependencies.subjectResolver.resolveImmutableGoogleUserId(
          lifecycleNotification,
          subject,
        );
      if (googleUserId === null) {
        await finishFailedWithoutMasking(
          this.#dependencies.receipts,
          claim.lease,
          nowMs,
        );
        return new Response(null, {
          headers: { "retry-after": "30" },
          status: 503,
        });
      }
      const task = RefreshGoogleDirectoryUserTaskSchema.parse({
        event: notification.event,
        googleUserId,
        notificationId: googleDirectoryNotificationId(notification),
        notificationPrimaryEmail: subject.primaryEmail,
        observedAt: new Date(nowMs).toISOString(),
        type: "identity.refresh-google-directory-user",
      });
      await this.#dependencies.queue.send(task);
    } catch (error) {
      await finishFailedWithoutMasking(
        this.#dependencies.receipts,
        claim.lease,
        nowMs,
      );
      logEvent("google_directory.lifecycle_enqueue_failed", {
        "channel_id": claim.lease.channelId,
        error: error instanceof Error ? error.message : String(error),
        "message_number": claim.lease.messageNumber,
      });
      throw error;
    }
    try {
      await this.#dependencies.receipts.finish(claim.lease, "enqueued", nowMs);
    } catch (error) {
      logEvent("google_directory.lifecycle_receipt_failure_after_enqueue", {
        "channel_id": claim.lease.channelId,
        error: error instanceof Error ? error.message : String(error),
        "message_number": claim.lease.messageNumber,
      });
      return new Response(null, { status: 202 });
    }
    return new Response(null, { status: 202 });
  }
}
