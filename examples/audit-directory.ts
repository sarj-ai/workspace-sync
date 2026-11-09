import { readFile } from "node:fs/promises";

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

function requiredEnvironment(name: string): string {
  // eslint-disable-next-line @sarj/no-raw-env -- This standalone CLI validates each credential here before constructing a provider client.
  const value = process.env[name];
  if (!value?.trim()) throw new Error(`Missing environment variable: ${name}`);
  return value;
}

const directory = new GoogleDirectoryClient({
  adminSubject: policy.org.googleAdminSubject,
  privateKey: requiredEnvironment("GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY"),
  serviceAccountEmail: requiredEnvironment("GOOGLE_SERVICE_ACCOUNT_EMAIL"),
  userProject: policy.org.googleUserProject,
});
const users = await directory.listAllUsers(
  crypto.randomUUID(),
  Date.now() + 60_000,
);
process.stdout.write(`Read ${String(users.length)} Directory users.\n`);
