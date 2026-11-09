import metadata from "../../../package.json" with { type: "json" };

export const providers = [
  {
    id: "google",
    label: "Google Workspace",
    icon: "google.svg",
    module: "org-sync/google-directory-client",
    detail: "People, teams and account status",
  },
  {
    id: "slack",
    label: "Slack",
    icon: "slack.svg",
    module: "org-sync/service",
    detail: "Profiles, groups and channels",
  },
  {
    id: "github",
    label: "GitHub",
    icon: "github.svg",
    module: "github-access-audit/service",
    detail: "Access audits and reviewed changes",
  },
  {
    id: "linear",
    label: "Linear",
    icon: "linear.svg",
    module: "workspace-directory/linear-profile-sync",
    detail: "Profiles and workspace access",
  },
  {
    id: "pagerduty",
    label: "PagerDuty",
    icon: "pagerduty.svg",
    module: "workspace-directory/pagerduty-team-sync",
    detail: "Teams and memberships",
  },
  {
    id: "sentry",
    label: "Sentry",
    icon: "sentry.svg",
    module: "workspace-directory/sentry-workspace-sync",
    detail: "Teams and memberships",
  },
  {
    id: "trycomp",
    label: "Comp AI",
    icon: "trycomp.png",
    module: "trycomp/service",
    detail: "Account activation and deactivation",
  },
  {
    id: "attio",
    label: "Attio",
    icon: "attio.ico",
    module: "identity-provisioning/attio-deprovision-authority-refresh",
    detail: "Checks for reviewed deprovisioning",
  },
] as const;

export const providerIcon = (icon: string): string =>
  new URL(`brand/${icon}`, metadata.homepage).pathname;

export const architecture = {
  nodes: [
    { ...providers[0], kind: "source", x: 0, y: 300 },
    {
      id: "plan",
      label: "Preview changes",
      detail: "Compare Google with provider data",
      kind: "compute",
      module: "org-sync/model",
      icon: null,
      x: 280,
      y: 300,
    },
    {
      id: "review",
      label: "Review changes",
      detail: "Your application approves the plan",
      kind: "host",
      module: "org-sync/service",
      icon: null,
      x: 560,
      y: 300,
    },
    {
      id: "apply",
      label: "Apply changes",
      detail: "Check current data, update and verify",
      kind: "write",
      module: "org-sync/service",
      icon: null,
      x: 840,
      y: 300,
    },
    ...providers.slice(1).map((provider, index) => ({
      ...provider,
      kind: "provider",
      x: 1120,
      y: index * 100,
    })),
  ],
  edges: [
    { source: "google", target: "plan" },
    { source: "plan", target: "review" },
    { source: "review", target: "apply" },
    ...providers
      .slice(1)
      .map((provider) => ({ source: "apply", target: provider.id })),
  ],
} as const;

export function architectureMermaid(): string {
  return [
    "flowchart LR",
    ...architecture.nodes.map((node) =>
      node.icon === null
        ? `  ${node.id}["${node.label}"]:::${node.kind}`
        : `  ${node.id}@{ img: "${new URL(`brand/${node.icon}`, metadata.homepage).href}", label: "${node.label}", h: 40, constraint: "on" }`,
    ),
    ...architecture.edges.map((edge) => `  ${edge.source} --> ${edge.target}`),
    "  classDef compute fill:#eef0ff,stroke:#465be8,color:#12141a,rx:10,ry:10",
    "  classDef host fill:#fff,stroke:#465be8,stroke-dasharray:5 4,color:#12141a,rx:10,ry:10",
    "  classDef write fill:#e7f5f1,stroke:#16806d,color:#12141a,rx:10,ry:10",
    "",
  ].join("\n");
}
