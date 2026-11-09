import { readFile } from "node:fs/promises";

import { z } from "zod";

import {
  configureWorkspaceSyncPolicy,
  getWorkspaceSyncPolicy,
} from "../src/configuration.ts";
import { GoogleDirectoryClient } from "../src/org-sync/google-directory-client.ts";

const policyPath = process.argv[2];
if (!policyPath)
  throw new Error("Usage: node audit-directory.ts /path/to/host-policy.json");
const input: unknown = JSON.parse(await readFile(policyPath, "utf8"));
configureWorkspaceSyncPolicy(input);
const policy = getWorkspaceSyncPolicy();

const credentials = z
  .object({
    GOOGLE_SERVICE_ACCOUNT_EMAIL: z.email(),
    GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY: z.string().trim().min(1),
  })
  // eslint-disable-next-line @sarj/no-raw-env -- Zod validates this standalone CLI's credentials before constructing a provider client.
  .parse(process.env);

const directory = new GoogleDirectoryClient({
  adminSubject: policy.org.googleAdminSubject,
  privateKey: credentials.GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY,
  serviceAccountEmail: credentials.GOOGLE_SERVICE_ACCOUNT_EMAIL,
  userProject: policy.org.googleUserProject,
});
const users = await directory.listAllUsers(
  crypto.randomUUID(),
  Date.now() + 60_000,
);
process.stdout.write(`Read ${String(users.length)} Directory users.\n`);
