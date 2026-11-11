import type { WorkspaceDirectoryRuntime } from "./runtime-contract.ts";

export function readWorkspaceSourceFingerprint(
  runtime: WorkspaceDirectoryRuntime,
  resourceId: string,
): Promise<null | string> {
  switch (resourceId) {
    case "directory-users":
      return runtime.readAuthorityFingerprint();
    case "github-access-authority":
      return runtime.readGitHubAccessAuthorityFingerprint();
    case "organization-identities":
      return runtime.readGithubIdentitySourceFingerprint();
    case "trycomp-authority":
      return runtime.readTrycompSourceFingerprint();
    case "slack-names-authority":
    case "linear-profiles-authority":
      if (runtime.readNameSourceFingerprint === undefined)
        throw new Error("workspace_branch_name_source_unavailable");
      return runtime.readNameSourceFingerprint(
        resourceId === "slack-names-authority"
          ? "slack-names"
          : "linear-profiles",
      );
    default:
      throw new Error("workspace_branch_source_unsupported");
  }
}
