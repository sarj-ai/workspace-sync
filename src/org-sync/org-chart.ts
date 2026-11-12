import { type HierarchyPointNode, hierarchy, tree } from "d3-hierarchy";

import { normalizeIdentityEmail } from "../identity-sync/normalize-identity-email.ts";
import {
  type GoogleDirectoryUser,
  type GoogleGitHubProfile,
  type GoogleOrganization,
  googleGitHubProfile,
  googleLinkedInUrl,
  isActiveGoogleDirectoryUser,
  isBotGoogleDirectoryUser,
  ORG_SYNC_DEPARTMENTS,
} from "./model.ts";

const COLORS: Readonly<Record<string, string>> = {
  Engineering: "#0b4778",
  Finance: "#315f7a",
  Marketing: "#7a4c00",
  "Needs placement": "#a61b1b",
  Operations: "#176b61",
  People: "#96352c",
  Product: "#594078",
  Sales: "#9d3f29",
};
const DEFAULT_COLOR = "#1a1a2e";
const NODE_WIDTH = 230;
const NODE_HEIGHT = 94;
const HORIZONTAL_GAP = 92;
const VERTICAL_GAP = 22;
const OUTER_MARGIN = 44;
const MAX_DIMENSION = 20_000;
const MAX_SVG_BYTES = 2_000_000;

export interface OrgChartPolicy {
  allowedEmptyDepartmentGoogleUserIds: readonly string[];
  excludedGoogleUserIds: readonly string[];
  expectedRootGoogleUserIds: readonly string[];
  minimumGoogleParticipants: number;
  protectedDepartedGoogleUserIds: readonly string[];
}

export interface OrgChartArtifact {
  people: number;
  svg: string;
}

export interface ChartPerson {
  department: string;
  email: string;
  githubProfile: GoogleGitHubProfile | null;
  id: string;
  linkedinUrl: null | string;
  managerId: null | string;
  name: string;
  title: string;
}

interface ChartTree {
  children: ChartTree[];
  person: ChartPerson | null;
}

interface ChartContext {
  allowedEmptyDepartments: ReadonlySet<string>;
  approvedDepartments: ReadonlySet<string>;
  directoryByEmail: ReadonlyMap<string, GoogleDirectoryUser>;
  emailToId: ReadonlyMap<string, string>;
  roots: ReadonlySet<string>;
}

interface ChartPosition {
  depth: number;
  y: number;
}

interface ChartLayout {
  height: number;
  nodes: HierarchyPointNode<ChartTree>[];
  positions: ReadonlyMap<string, ChartPosition>;
  width: number;
}

const DEFAULT_POLICY: OrgChartPolicy = {
  allowedEmptyDepartmentGoogleUserIds: [],
  excludedGoogleUserIds: [],
  expectedRootGoogleUserIds: [],
  minimumGoogleParticipants: 1,
  protectedDepartedGoogleUserIds: [],
};

export function renderOrgChartSvg(
  users: readonly GoogleDirectoryUser[],
  excludedGoogleUserIds: readonly string[] = [],
): string {
  return renderOrgChartArtifact(users, {
    ...DEFAULT_POLICY,
    excludedGoogleUserIds,
  }).svg;
}

export function renderOrgChartArtifact(
  users: readonly GoogleDirectoryUser[],
  policy: OrgChartPolicy,
): OrgChartArtifact {
  const people = chartPeople(users, policy);
  if (people.length === 0)
    throw new Error("Cannot render an empty Google organization chart");
  const children = childrenByManager(people);
  const layout = leftToRightDepthBoundedChartLayout(people, children);
  const output = [
    `<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-labelledby="org-title org-desc" viewBox="0 0 ${String(layout.width)} ${String(layout.height)}" width="100%" preserveAspectRatio="xMidYMin meet" style="max-width:100%;height:auto" font-family="Inter,system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif">`,
    '<title id="org-title">Organization chart</title>',
    `<desc id="org-desc">${String(people.length)} active people. Google Workspace Directory is the source of record.</desc>`,
    '<rect width="100%" height="100%" fill="white"/>',
    `<text x="${String(layout.width / 2)}" y="22" text-anchor="middle" font-size="15" font-weight="700" fill="#202124">Organization · ${String(people.length)} people · Google Workspace</text>`,
  ];
  appendLinks(output, layout, children);
  appendPeopleInHierarchyOrder(output, layout);
  output.push("</svg>");
  const svg = output.join("");
  const bytes = new TextEncoder().encode(svg).byteLength;
  if (bytes > MAX_SVG_BYTES) {
    throw new Error(
      `Google organization chart exceeds safe size: ${String(bytes)} bytes`,
    );
  }
  return { people: people.length, svg };
}

export function chartPeople(
  users: readonly GoogleDirectoryUser[],
  policy: OrgChartPolicy,
): ChartPerson[] {
  const active = orgChartParticipants(users, policy);
  const roots = new Set(policy.expectedRootGoogleUserIds);
  const context: ChartContext = {
    allowedEmptyDepartments: new Set(
      policy.allowedEmptyDepartmentGoogleUserIds,
    ),
    approvedDepartments: new Set<string>(ORG_SYNC_DEPARTMENTS),
    directoryByEmail: directoryEmailIndex(users),
    emailToId: activeEmailIndex(active),
    roots,
  };
  const people = active
    .map((user) => chartPerson(user, context))
    .toSorted((left, right) => left.email.localeCompare(right.email));
  validateParticipantLinks(people);
  validateExpectedRoots(people, roots);
  return people;
}

function managerEmail(user: GoogleDirectoryUser): null | string {
  const managers = (user.relations ?? []).filter(
    (relation) => relation.type === "manager",
  );
  if (managers.length > 1) {
    throw new Error(
      `Google user ${user.id} has more than one manager relation`,
    );
  }
  const manager = managers[0]?.value
    ? normalizeIdentityEmail(managers[0].value)
    : undefined;
  return manager?.length ? manager : null;
}

export function orgChartParticipants(
  users: readonly GoogleDirectoryUser[],
  policy: OrgChartPolicy,
): GoogleDirectoryUser[] {
  const excluded = new Set(policy.excludedGoogleUserIds);
  const usersById = new Map(users.map((user) => [user.id, user]));
  if (usersById.size !== users.length)
    throw new Error("Google Directory returned duplicate immutable user IDs");
  for (const id of policy.protectedDepartedGoogleUserIds) {
    const user = usersById.get(id);
    if (user && isActiveGoogleDirectoryUser(user)) {
      throw new Error(
        `Protected departed Google account ${id} has been restored to active`,
      );
    }
  }
  const active = users.filter(
    (user) =>
      isActiveGoogleDirectoryUser(user) &&
      !isBotGoogleDirectoryUser(user) &&
      !excluded.has(user.id),
  );
  if (active.length < policy.minimumGoogleParticipants) {
    throw new Error(
      `Google org population ${String(active.length)} is below chart safety floor ${String(policy.minimumGoogleParticipants)}`,
    );
  }
  return active;
}

function activeEmailIndex(
  active: readonly GoogleDirectoryUser[],
): Map<string, string> {
  const emailToId = new Map<string, string>();
  for (const user of active) {
    const email = normalizeIdentityEmail(user.primaryEmail);
    if (emailToId.has(email))
      throw new Error(`Duplicate active Google email: ${email}`);
    emailToId.set(email, user.id);
  }
  return emailToId;
}

function directoryEmailIndex(
  users: readonly GoogleDirectoryUser[],
): Map<string, GoogleDirectoryUser> {
  const usersByEmail = new Map<string, GoogleDirectoryUser>();
  for (const user of users) {
    const email = normalizeIdentityEmail(user.primaryEmail);
    if (usersByEmail.has(email))
      throw new Error(`Duplicate Google email: ${email}`);
    usersByEmail.set(email, user);
  }
  return usersByEmail;
}

function chartPerson(
  user: GoogleDirectoryUser,
  context: ChartContext,
): ChartPerson {
  const organization = primaryOrganization(user);
  const identity = chartIdentity(user);
  const manager = managerEmail(user);
  if (context.roots.has(user.id) && manager) {
    throw new Error(
      `Expected Google reporting root ${user.id} unexpectedly has a manager`,
    );
  }
  const githubProfile = googleGitHubProfile(user);
  const linkedinUrl = googleLinkedInUrl(user);
  if (!organization)
    return needsPlacement(
      identity,
      githubProfile,
      linkedinUrl,
      "Google profile incomplete",
      null,
    );
  const managerId = resolvedManagerId(user, manager, context);
  const department = organization.department?.trim() ?? "";
  if (department && !context.approvedDepartments.has(department)) {
    throw new Error(
      `Google user ${user.id} has an unapproved department: ${department}`,
    );
  }
  if (!department && !context.allowedEmptyDepartments.has(user.id)) {
    return needsPlacement(
      identity,
      githubProfile,
      linkedinUrl,
      "Google department missing",
      managerId,
    );
  }
  if (!context.roots.has(user.id) && !managerId) {
    return needsPlacement(
      identity,
      githubProfile,
      linkedinUrl,
      "Google manager missing",
      null,
    );
  }
  return {
    ...identity,
    department,
    githubProfile,
    linkedinUrl,
    managerId,
    title: organization.title?.trim() ?? "",
  };
}

function resolvedManagerId(
  user: GoogleDirectoryUser,
  manager: null | string,
  context: Pick<ChartContext, "directoryByEmail" | "emailToId">,
): null | string {
  if (!manager) return null;
  const visited = new Set([normalizeIdentityEmail(user.primaryEmail)]);
  let managerEmailValue: null | string = manager;
  while (managerEmailValue) {
    if (visited.has(managerEmailValue)) {
      throw new Error(
        `Google manager chain for ${user.id} contains a cycle at ${managerEmailValue}`,
      );
    }
    visited.add(managerEmailValue);
    const activeManagerId = context.emailToId.get(managerEmailValue);
    if (activeManagerId) return activeManagerId;
    const inactiveManager = context.directoryByEmail.get(managerEmailValue);
    if (!inactiveManager || isActiveGoogleDirectoryUser(inactiveManager)) {
      throw new Error(
        `Google manager for ${user.id} cannot be resolved: ${managerEmailValue}`,
      );
    }
    managerEmailValue = managerEmail(inactiveManager);
  }
  throw new Error(
    `Google manager for ${user.id} has no active manager in its reporting chain`,
  );
}

function needsPlacement(
  identity: Pick<ChartPerson, "email" | "id" | "name">,
  githubProfile: GoogleGitHubProfile | null,
  linkedinUrl: null | string,
  title: string,
  managerId: null | string,
): ChartPerson {
  return {
    ...identity,
    department: "Needs placement",
    githubProfile,
    linkedinUrl,
    managerId,
    title,
  };
}

function chartIdentity(
  user: GoogleDirectoryUser,
): Pick<ChartPerson, "email" | "id" | "name"> {
  const email = normalizeIdentityEmail(user.primaryEmail);
  const fullName = user.name?.fullName?.trim();
  return {
    email,
    id: user.id,
    name: fullName?.length ? fullName : (email.split("@", 1)[0] ?? email),
  };
}

function primaryOrganization(
  user: GoogleDirectoryUser,
): GoogleOrganization | null {
  const primary = (user.organizations ?? []).filter(
    (organization) => organization.primary === true,
  );
  if (primary.length > 1) {
    throw new Error(
      `Google user ${user.id} has more than one primary organization`,
    );
  }
  return primary[0] ?? null;
}

function validateParticipantLinks(people: readonly ChartPerson[]): void {
  const participantIds = new Set(people.map((person) => person.id));
  for (const person of people) {
    if (person.managerId && !participantIds.has(person.managerId)) {
      throw new Error(
        `Google manager for ${person.id} is not an active org participant`,
      );
    }
    if (person.managerId === person.id)
      throw new Error(`Google user ${person.id} reports to itself`);
  }
  validateAcyclic(people);
}

function validateExpectedRoots(
  people: readonly ChartPerson[],
  roots: ReadonlySet<string>,
): void {
  for (const rootId of roots) {
    const root = people.find((person) => person.id === rootId);
    if (!root)
      throw new Error(
        `Expected Google reporting root ${rootId} is missing or inactive`,
      );
    if (root.managerId !== null)
      throw new Error(`Expected Google reporting root ${rootId} has a manager`);
  }
}

function validateAcyclic(people: readonly ChartPerson[]): void {
  const byId = new Map(people.map((person) => [person.id, person]));
  const complete = new Set<string>();
  for (const person of people) {
    const path = new Set<string>();
    let cursor: ChartPerson | undefined = person;
    while (cursor && !complete.has(cursor.id)) {
      if (path.has(cursor.id)) {
        throw new Error(
          `Google reporting graph contains a cycle involving ${cursor.id}`,
        );
      }
      path.add(cursor.id);
      cursor = cursor.managerId ? byId.get(cursor.managerId) : undefined;
    }
    for (const id of path) complete.add(id);
  }
}

function childrenByManager(
  people: readonly ChartPerson[],
): Map<string, ChartPerson[]> {
  const children = new Map<string, ChartPerson[]>();
  for (const person of people) {
    if (!person.managerId) continue;
    const reports = children.get(person.managerId) ?? [];
    reports.push(person);
    children.set(person.managerId, reports);
  }
  for (const reports of children.values()) {
    reports.sort(
      (left, right) =>
        left.department.localeCompare(right.department) ||
        left.email.localeCompare(right.email),
    );
  }
  return children;
}

function leftToRightDepthBoundedChartLayout(
  people: readonly ChartPerson[],
  children: ReadonlyMap<string, ChartPerson[]>,
): ChartLayout {
  const roots = people.filter((person) => person.managerId === null);
  if (roots.length === 0)
    throw new Error("Google organization chart has no reporting root");
  const branch = (person: ChartPerson): ChartTree => ({
    children: (children.get(person.id) ?? []).map(branch),
    person,
  });
  const d3Root = tree<ChartTree>()
    .nodeSize([NODE_HEIGHT + VERTICAL_GAP, NODE_WIDTH + HORIZONTAL_GAP])
    .separation((left, right) => (left.parent === right.parent ? 1 : 1.08))(
    hierarchy<ChartTree>({ children: roots.map(branch), person: null }),
  );
  const nodes = d3Root
    .descendants()
    .filter((node) => node.data.person !== null);
  if (nodes.length !== people.length) {
    throw new Error("Google organization chart layout omitted participants");
  }
  const minX = Math.min(...nodes.map((node) => node.x));
  const maxX = Math.max(...nodes.map((node) => node.x));
  const positions = new Map<string, ChartPosition>();
  for (const node of nodes) {
    const person = node.data.person;
    if (person)
      positions.set(person.id, { depth: node.depth - 1, y: node.x - minX });
  }
  const maxDepth = Math.max(
    ...positions.values().map((position) => position.depth),
  );
  const width = Math.ceil(
    (maxDepth + 1) * (NODE_WIDTH + HORIZONTAL_GAP) -
      HORIZONTAL_GAP +
      OUTER_MARGIN * 2,
  );
  const height = Math.ceil(maxX - minX + NODE_HEIGHT + 76);
  if (width > MAX_DIMENSION || height > MAX_DIMENSION) {
    throw new Error(
      `Google organization chart exceeds safe dimensions: ${String(width)}x${String(height)}`,
    );
  }
  return { height, nodes, positions, width };
}

function xPosition(depth: number): number {
  return OUTER_MARGIN + depth * (NODE_WIDTH + HORIZONTAL_GAP);
}

function yPosition(position: ChartPosition): number {
  return 36 + position.y;
}

function requiredPosition(
  positions: ReadonlyMap<string, ChartPosition>,
  personId: string,
): ChartPosition {
  const position = positions.get(personId);
  if (!position) throw new Error(`Missing layout position for ${personId}`);
  return position;
}

function appendLinks(
  output: string[],
  layout: ChartLayout,
  children: ReadonlyMap<string, ChartPerson[]>,
): void {
  for (const node of layout.nodes) {
    const person = node.data.person;
    if (!person) continue;
    const position = requiredPosition(layout.positions, person.id);
    const reports = children.get(person.id);
    if (!reports) continue;
    for (const report of reports) {
      const child = requiredPosition(layout.positions, report.id);
      const x1 = xPosition(position.depth) + NODE_WIDTH;
      const y1 = yPosition(position) + NODE_HEIGHT / 2;
      const x2 = xPosition(child.depth);
      const y2 = yPosition(child) + NODE_HEIGHT / 2;
      const middle = (x1 + x2) / 2;
      output.push(
        `<path d="M${String(x1)},${String(y1)} L${String(middle)},${String(y1)} L${String(middle)},${String(y2)} L${String(x2)},${String(y2)}" stroke="#8a9099" fill="none" stroke-width="1.5"/>`,
      );
    }
  }
}

function appendPeopleInHierarchyOrder(
  output: string[],
  layout: ChartLayout,
): void {
  for (const node of layout.nodes) {
    const person = node.data.person;
    if (!person) continue;
    appendPerson(output, person, requiredPosition(layout.positions, person.id));
  }
}

function appendPerson(
  output: string[],
  person: ChartPerson,
  position: ChartPosition,
): void {
  const left = xPosition(position.depth);
  const top = yPosition(position);
  const accessible = xml(
    [person.name, person.title, person.department || "Team not set"]
      .filter(Boolean)
      .join("; "),
  );
  output.push(`<g role="group" aria-label="${accessible}">`);
  output.push(
    `<rect x="${String(left)}" y="${String(top)}" width="${String(NODE_WIDTH)}" height="${String(NODE_HEIGHT)}" rx="10" fill="${COLORS[person.department] ?? DEFAULT_COLOR}" stroke="#202124" stroke-width="0.7"/>`,
  );
  output.push(
    `<text x="${String(left + NODE_WIDTH / 2)}" y="${String(top + 25)}" text-anchor="middle" font-size="13" font-weight="700" fill="white">${xml(clipped(person.name, 31))}</text>`,
  );
  output.push(
    `<text x="${String(left + NODE_WIDTH / 2)}" y="${String(top + 51)}" text-anchor="middle" font-size="10.5" fill="white">${xml(clipped(person.title, 38))}</text>`,
  );
  output.push(
    `<text x="${String(left + NODE_WIDTH / 2)}" y="${String(top + 75)}" text-anchor="middle" font-size="10.5" font-weight="600" fill="#ffffff">${xml(clipped(person.department || "Team not set", 34))}</text>`,
  );
  output.push("</g>");
}

function xml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function clipped(value: string, max: number): string {
  // eslint-disable-next-line @typescript-eslint/no-misused-spread -- Clip by Unicode code point.
  const characters = [...value];
  return characters.length <= max
    ? value
    : `${characters.slice(0, max - 1).join("")}…`;
}
