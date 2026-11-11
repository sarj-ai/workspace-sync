import metadata from "../../../package.json" with { type: "json" };

export const providers = [
  {
    id: "google",
    label: "Google Workspace",
    icon: "google.svg",
    module: "org-sync/google-directory-client",
    detail: "People, groups and account status",
  },
  {
    id: "slack",
    label: "Slack",
    icon: "slack.svg",
    module: "org-sync/service",
    detail: "Managed profile fields",
    scope: "Update at most one Slack profile per apply.",
    guard: "Only managed fields change; a different plan hash stops the apply.",
  },
  {
    id: "github",
    label: "GitHub",
    icon: "github.svg",
    module: "github-access-audit/service",
    detail: "Read-only access audit",
    scope:
      "Compare Google authority with GitHub organization, team and repository access.",
    guard: "The audit reports proposed changes. It does not apply them.",
  },
  {
    id: "linear",
    label: "Linear",
    icon: "linear.svg",
    module: "workspace-directory/linear-profile-sync",
    detail: "Repair default full names",
    scope:
      "Replace an email-based default full name with the Google full name.",
    guard:
      "Keep custom names and nicknames. Require an active, unambiguous email match.",
  },
  {
    id: "pagerduty",
    label: "PagerDuty",
    icon: "pagerduty.svg",
    module: "workspace-directory/pagerduty-team-sync",
    detail: "Pinned team memberships",
    scope:
      "Plan membership changes for explicitly mapped Google groups and PagerDuty teams.",
    guard:
      "Missing credentials, incomplete authority or unreviewed mappings block the plan.",
  },
  {
    id: "sentry",
    label: "Sentry",
    icon: "sentry.svg",
    module: "workspace-directory/sentry-workspace-sync",
    detail: "Managed team and invitations",
    scope:
      "Reconcile the managed team and invitations, then verify the exact target.",
    guard: "Organization removals require a separate signed parent workflow.",
  },
  {
    id: "trycomp",
    label: "Comp AI",
    icon: "trycomp.png",
    module: "trycomp/service",
    detail: "Reviewed account lifecycle",
    scope:
      "Apply reviewed account changes with fresh identity authority and provider readback.",
    guard:
      "Retained operation state and delivery evidence govern retries after uncertain responses.",
  },
  {
    id: "attio",
    label: "Attio",
    icon: "attio.ico",
    module: "identity-provisioning/attio-deprovision-authority-refresh",
    detail: "Capture authority for review",
    scope:
      "Capture Attio and Google evidence for a later reviewed deprovisioning workflow.",
    guard:
      "Refreshing this snapshot does not delete or deactivate an Attio account.",
  },
] as const;

export const [google, ...integrations] = providers;
export type Integration = (typeof integrations)[number];
export type IntegrationId = Integration["id"];

export interface FlowStage {
  readonly id: string;
  readonly label: string;
  readonly detail: string;
  readonly kind: "source" | "compute" | "host" | "write" | "provider";
  readonly icon: string | null;
  readonly module: string;
  readonly input: string;
  readonly actions: readonly string[];
  readonly output: string;
  readonly guard: string;
}

export const providerIcon = (icon: string): string =>
  new URL(`brand/${icon}`, metadata.homepage).pathname;
export const apiHref = (module: string): string =>
  new URL(`api/${module}/`, metadata.homepage).pathname;

export function integrationById(id: IntegrationId): Integration {
  const provider = integrations.find((item) => item.id === id);
  if (!provider) throw new Error(`Unknown integration: ${id}`);
  return provider;
}

function googleStage(): FlowStage {
  return {
    id: "google",
    label: "Read Google",
    detail: google.detail,
    kind: "source",
    icon: google.icon,
    module: google.module,
    input: "A Google Directory client supplied by your application.",
    actions: [
      "Read directory users and the groups needed by this workflow.",
      "Use Google identity and account status as authority for the comparison.",
    ],
    output: "A directory snapshot used to decide the desired provider state.",
    guard:
      "The host supplies credentials and policy. Reading the directory does not change accounts.",
  };
}

export function workflowFor(id: IntegrationId): readonly FlowStage[] {
  const provider = integrationById(id);
  if (id === "github") return githubWorkflow(provider);
  if (id === "attio") return attioWorkflow(provider);
  const slack = id === "slack";
  const hostApplies = id === "pagerduty";
  return [
    googleStage(),
    {
      id: "plan",
      label: "Plan changes",
      detail: "Compare desired and current state",
      kind: "compute",
      icon: null,
      module: provider.module,
      input: `Google authority, current ${provider.label} data and the host’s policy.`,
      actions: [
        "Preview the integration’s changes without writing to the provider.",
        "Build the proposed actions and a hash identifying the reviewed plan.",
      ],
      output:
        "A read-only plan: proposed changes, diagnostics and a plan hash.",
      guard: provider.guard,
    },
    {
      id: "review",
      label: "Review in your app",
      detail: "Approve the exact plan",
      kind: "host",
      icon: null,
      module: provider.module,
      input: "The proposed actions, diagnostics and plan hash.",
      actions: [
        "Show the changes in the consuming application.",
        "Keep approval tied to the exact plan; the package does not provide an approval UI.",
      ],
      output:
        "An approved plan or action passed to this integration’s apply workflow.",
      guard:
        "A preview is not permission to write. Your application owns approval and credentials.",
    },
    {
      id: "apply",
      label: hostApplies ? "Host checks & writes" : "Recheck before writing",
      detail: "Fresh data must match approval",
      kind: "write",
      icon: null,
      module: hostApplies
        ? "workspace-directory/pagerduty-team-client"
        : provider.module,
      input: `The reviewed plan and fresh ${provider.label} evidence.`,
      actions: [
        hostApplies
          ? "The host checks fresh evidence against the approved plan and action preconditions."
          : "Recheck the plan and the selected target before the provider operation.",
        slack
          ? "Apply at most one profile; an optional identity budget shares the person limit across workflows."
          : "Use this integration’s write authority, action limits and retry contract.",
      ],
      output:
        "The approved action is allowed to reach the provider, or execution stops.",
      guard: hostApplies
        ? "The planner does not apply changes. The host must enforce approval and preconditions when using the provider client."
        : "If the approved evidence no longer matches, stop and review a new plan.",
    },
    {
      id: "provider",
      label: provider.label,
      detail: provider.detail,
      kind: "provider",
      icon: provider.icon,
      module: provider.module,
      input: "A selected action that passed the workflow’s write checks.",
      actions: [
        provider.scope,
        "Send the operation through the supplied provider client.",
      ],
      output: "The provider’s response. Verification still follows.",
      guard: provider.guard,
    },
    {
      id: "verify",
      label: "Verify the result",
      detail: "Read the provider state back",
      kind: "compute",
      icon: null,
      module: provider.module,
      input: "The expected result and the provider state after the operation.",
      actions: [
        "Read the affected profile, account or membership back.",
        "Compare the exact managed target with the approved result.",
      ],
      output:
        "A verified result, or a failure requiring the host’s recovery workflow.",
      guard:
        id === "trycomp"
          ? provider.guard
          : "A successful HTTP response alone does not prove the desired state. The host handles a failed verification.",
    },
  ];
}

function githubWorkflow(provider: Integration): readonly FlowStage[] {
  return [
    googleStage(),
    {
      id: "provider",
      label: "Read GitHub",
      detail: "Organization, teams and repositories",
      kind: "provider",
      icon: provider.icon,
      module: provider.module,
      input: "GitHub and Google capture clients, supplied by the host.",
      actions: [
        "Capture GitHub access and Google authority in parallel under a shared deadline.",
        "Read organization members, team mappings and repository access.",
      ],
      output: "Provider snapshots for an access comparison.",
      guard: "This service reads access; it does not grant or revoke it.",
    },
    {
      id: "plan",
      label: "Compare access",
      detail: "Correlate identities and permissions",
      kind: "compute",
      icon: null,
      module: provider.module,
      input: "Google authority, GitHub access and the configured audit policy.",
      actions: [
        "Correlate Google and GitHub identities.",
        "Compare effective repository and team access, including reviewed grants and exceptions.",
      ],
      output: "An access report with proposed changes and supporting evidence.",
      guard:
        "Grace periods, pinned mappings and retained grants affect the report.",
    },
    {
      id: "review",
      label: "Review the report",
      detail: "Your application decides what follows",
      kind: "host",
      icon: null,
      module: provider.module,
      input: "The access audit report.",
      actions: [
        "Inspect proposed changes and unresolved identities.",
        "Use a separate reviewed provisioning workflow if a change is needed.",
      ],
      output: "A host decision; the audit itself performs no provider writes.",
      guard: provider.guard,
    },
  ];
}

function attioWorkflow(provider: Integration): readonly FlowStage[] {
  return [
    {
      id: "provider",
      label: "Capture Attio",
      detail: "Members and available SCIM evidence",
      kind: "provider",
      icon: provider.icon,
      module: provider.module,
      input: "The host’s Attio capture function.",
      actions: [
        "Capture Attio workspace members and available SCIM evidence.",
        "Validate the returned authority snapshot before continuing.",
      ],
      output: "Validated Attio evidence and its capture timestamp.",
      guard: "A failed or invalid capture stops the refresh.",
    },
    {
      ...googleStage(),
      label: "Capture Google last",
      detail: "Fresh lifecycle authority",
      module: provider.module,
      input: "Validated Attio evidence and the host’s Google capture function.",
      actions: [
        "Read Google after Attio under the host’s shared deadline.",
        "Validate current and deleted Google identities as lifecycle authority.",
      ],
      output: "Validated Google evidence paired with the Attio capture.",
      guard:
        "Google is observed last. Snapshot freshness is anchored to the older Attio timestamp.",
    },
    {
      id: "store",
      label: "Replace the snapshot",
      detail: "One atomic store write",
      kind: "compute",
      icon: null,
      module: provider.module,
      input: "Both validated captures, their schema version and capture time.",
      actions: [
        "Combine Attio and Google evidence.",
        "Replace the authority snapshot through the host-supplied store.",
      ],
      output: "A stored authority snapshot and capture counts.",
      guard: "Both captures must succeed before the single replacement write.",
    },
    {
      id: "review",
      label: "Use in a reviewed workflow",
      detail: "Evidence for a later decision",
      kind: "host",
      icon: null,
      module: provider.module,
      input: "The stored authority snapshot.",
      actions: [
        "Supply this evidence to a separate reviewed deprovisioning workflow.",
        "Keep approval, provider writes and operational state in the consuming application.",
      ],
      output: "Fresh evidence for review, with no Attio account mutation.",
      guard: provider.guard,
    },
  ];
}

export function workflowEdges(id: IntegrationId) {
  const stages = workflowFor(id);
  const labels =
    id === "attio"
      ? ["validated", "combine", "stored"]
      : ["read", "plan hash", "approved", "write", "read back"];
  const connections =
    id === "github"
      ? [
          { from: 0, to: 2, label: "Google" },
          { from: 1, to: 2, label: "GitHub" },
          { from: 2, to: 3, label: "report" },
        ]
      : stages.slice(1).map((_stage, index) => ({
          from: index,
          to: index + 1,
          label: labels[index] ?? "",
        }));
  return connections.map(({ from, to, label }) => {
    const source = stages[from];
    const target = stages[to];
    if (!source || !target)
      throw new RangeError("Workflow edge references a missing stage");
    return { source: source.id, target: target.id, from, to, label };
  });
}

export function architectureMermaid(): string {
  return [
    "flowchart LR",
    ...integrations.flatMap((provider) => {
      const stages = workflowFor(provider.id);
      return [
        `  subgraph ${provider.id}["${provider.label}"]`,
        ...stages.map(
          (stage, index) =>
            `    ${provider.id}_${stage.id}["${String(index + 1)}. ${stage.label}"]`,
        ),
        ...workflowEdges(provider.id).map(
          (edge) =>
            `    ${provider.id}_${edge.source} -->|${edge.label}| ${provider.id}_${edge.target}`,
        ),
        "  end",
      ];
    }),
    "",
  ].join("\n");
}
