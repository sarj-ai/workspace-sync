import type { GoogleDirectoryUser } from "./model.ts";
import {
  NUNITO_REGULAR_BASE64,
  NUNITO_SEMIBOLD_BASE64,
} from "./org-chart-fonts.ts";
import {
  type ChartPerson,
  chartPeople,
  type OrgChartPolicy,
} from "./org-chart.ts";

const MAX_HTML_BYTES = 8_000_000;
const MAX_EMBEDDED_PHOTO_BYTES = 5_000_000;
const NO_TEAM = "No team";
const DEPARTMENT_COLORS: Readonly<Record<string, string>> = {
  Engineering: "#4674c8",
  Finance: "#3e7894",
  Marketing: "#b37534",
  "Needs placement": "#bd5360",
  Operations: "#3a8176",
  People: "#a95e7d",
  Product: "#7163a6",
  Sales: "#b7634c",
};

export interface OrgChartHtmlArtifact {
  html: string;
  people: number;
  photos: number;
}

export function renderOrgChartHtml(
  users: readonly GoogleDirectoryUser[],
  policy: OrgChartPolicy,
  profilePhotos: ReadonlyMap<string, string> = new Map(),
): OrgChartHtmlArtifact {
  const people = chartPeople(users, policy);
  if (people.length === 0)
    throw new Error("Cannot render an empty Google organization chart");

  const byId = new Map(people.map((person) => [person.id, person]));
  const reportsByManager = groupReports(people);
  const photos = validatedPhotos(people, profilePhotos);
  const rootIds = new Set(policy.expectedRootGoogleUserIds);
  const roots = people
    .filter((person) => rootIds.has(person.id))
    .toSorted((left, right) => left.name.localeCompare(right.name));
  const teams = [...new Set(people.map(teamName))].toSorted((a, b) =>
    a.localeCompare(b),
  );
  const departments = teams
    .filter((team) => team !== NO_TEAM)
    .map((team) => ({
      people: people
        .filter(
          (person) => !rootIds.has(person.id) && teamName(person) === team,
        )
        .toSorted((left, right) => left.name.localeCompare(right.name)),
      team,
    }))
    .filter(({ people: members }) => members.length > 0);
  const sections = [
    ...(roots.length > 0 ? [{ people: roots, team: "Founders" }] : []),
    ...departments,
  ].toSorted((left, right) => left.team.localeCompare(right.team));
  const alphabeticalPeople = people.toSorted((left, right) =>
    left.name.localeCompare(right.name),
  );
  const hierarchyRoots = people
    .filter((person) => !person.managerId || !byId.has(person.managerId))
    .toSorted((left, right) => left.name.localeCompare(right.name));

  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Organization Chart</title><style>${styles()}</style></head>
<body><main>
  <h1 class="sr-only">Organization Chart</h1>
  <header class="toolbar">
    <div class="view-switch" role="tablist" aria-label="Directory view">
      <button id="teams-tab" type="button" role="tab" tabindex="0" aria-selected="true" aria-controls="teams-view">Teams</button>
      <button id="hierarchy-tab" type="button" role="tab" tabindex="-1" aria-selected="false" aria-controls="hierarchy-view">Tree</button>
      <button id="linkedin-tab" type="button" role="tab" tabindex="-1" aria-selected="false" aria-controls="linkedin-view">Profiles</button>
    </div>
  </header>
  <div class="teams" id="teams-view" role="tabpanel" aria-labelledby="teams-tab">${sections.map(({ people: members, team }) => teamPanel(team, members, byId, reportsByManager, photos)).join("")}</div>
  <section class="hierarchy-view" id="hierarchy-view" role="tabpanel" aria-labelledby="hierarchy-tab" hidden>
    <ul class="hierarchy-roots" aria-label="Reporting tree">${hierarchyRoots.map((person) => hierarchyNode(person, reportsByManager, photos, new Set())).join("")}</ul>
  </section>
  <section class="linkedin-view" id="linkedin-view" role="tabpanel" aria-labelledby="linkedin-tab" hidden>
    <div class="table-wrap"><table><thead><tr><th scope="col">Name</th><th scope="col">Role</th><th scope="col">Team</th><th scope="col">GitHub</th><th scope="col">LinkedIn</th></tr></thead><tbody>${alphabeticalPeople.map((person) => profileRow(person, photos)).join("")}</tbody></table></div>
  </section>
  <footer>Manager, team, and role come from Google Workspace.</footer>
</main><script data-cfasync="false">${script()}</script></body></html>`;

  const bytes = new TextEncoder().encode(html).byteLength;
  if (bytes > MAX_HTML_BYTES) {
    throw new Error(
      `Google organization chart exceeds safe size: ${String(bytes)} bytes`,
    );
  }
  return { html, people: people.length, photos: photos.size };
}

function hierarchyNode(
  person: ChartPerson,
  reports: ReadonlyMap<string, readonly ChartPerson[]>,
  photos: ReadonlyMap<string, string>,
  ancestors: ReadonlySet<string>,
): string {
  if (ancestors.has(person.id))
    throw new Error(`Google reporting cycle includes ${person.email}`);
  const nextAncestors = new Set(ancestors).add(person.id);
  const directReports = reports.get(person.id) ?? [];
  const role = person.title || teamName(person);
  const subtitle =
    role === teamName(person) ? role : `${role} · ${teamName(person)}`;
  const photo = photos.get(person.id);
  const avatar = photo
    ? `<img src="${attribute(photo)}" alt="" loading="lazy" decoding="async">`
    : `<span aria-hidden="true">${escapeHtml(initials(person.name))}</span>`;
  return `<li><a class="hierarchy-person person-jump" href="#${attribute(personAnchor(person.id))}"><span class="tree-avatar">${avatar}</span><span><strong>${escapeHtml(person.name)}</strong><small>${escapeHtml(subtitle)}</small></span>${directReports.length > 0 ? `<span class="tree-count" aria-label="${String(directReports.length)} direct reports">${String(directReports.length)}</span>` : ""}</a>${directReports.length > 0 ? `<ul>${directReports.map((report) => hierarchyNode(report, reports, photos, nextAncestors)).join("")}</ul>` : ""}</li>`;
}

function teamName(person: ChartPerson): string {
  return person.department || NO_TEAM;
}

function groupReports(
  people: readonly ChartPerson[],
): ReadonlyMap<string, ChartPerson[]> {
  const output = new Map<string, ChartPerson[]>();
  for (const person of people) {
    if (!person.managerId) continue;
    const reports = output.get(person.managerId) ?? [];
    reports.push(person);
    output.set(person.managerId, reports);
  }
  for (const reports of output.values())
    reports.sort((a, b) => a.name.localeCompare(b.name));
  return output;
}

function validatedPhotos(
  people: readonly ChartPerson[],
  profilePhotos: ReadonlyMap<string, string>,
): ReadonlyMap<string, string> {
  const participantIds = new Set(people.map((person) => person.id));
  const output = new Map<string, string>();
  let bytes = 0;
  for (const [id, value] of [...profilePhotos].toSorted(([left], [right]) =>
    left.localeCompare(right),
  )) {
    if (!participantIds.has(id)) continue;
    if (
      !/^data:image\/(?:jpeg|png|webp);base64,[A-Za-z0-9+/]+={0,2}$/u.test(
        value,
      )
    ) {
      throw new Error(`Google profile photo for ${id} has an unsafe data URL`);
    }
    bytes += new TextEncoder().encode(value).byteLength;
    if (bytes > MAX_EMBEDDED_PHOTO_BYTES)
      throw new Error("Google profile photos exceed safe total size");
    output.set(id, value);
  }
  return output;
}

function teamPanel(
  team: string,
  people: readonly ChartPerson[],
  byId: ReadonlyMap<string, ChartPerson>,
  reports: ReadonlyMap<string, readonly ChartPerson[]>,
  photos: ReadonlyMap<string, string>,
): string {
  const id = `team-${slug(team)}`;
  return `<section class="team-panel directory-section" style="--team:${color(team)}" aria-labelledby="${attribute(id)}"><div class="section-heading"><h2 id="${attribute(id)}">${escapeHtml(team)}</h2><span>${String(people.length)}</span></div><div class="people-grid">${people.map((person) => card(person, byId, reports, photos)).join("")}</div></section>`;
}

function card(
  person: ChartPerson,
  byId: ReadonlyMap<string, ChartPerson>,
  reports: ReadonlyMap<string, readonly ChartPerson[]>,
  photos: ReadonlyMap<string, string>,
): string {
  const manager = person.managerId ? byId.get(person.managerId) : undefined;
  const directReports = reports.get(person.id) ?? [];
  const role = person.title || teamName(person);
  const photo = photos.get(person.id);
  const avatar = photo
    ? `<img src="${attribute(photo)}" alt="" loading="lazy" decoding="async">`
    : `<span aria-hidden="true">${escapeHtml(initials(person.name))}</span>`;
  const managerValue = manager
    ? `<a class="person-jump" href="#${attribute(personAnchor(manager.id))}">${escapeHtml(manager.name)}</a>`
    : "—";
  const managesValue = directReports
    .map(
      (report) =>
        `<a class="person-jump" href="#${attribute(personAnchor(report.id))}">${escapeHtml(report.name)}</a>`,
    )
    .join(", ");
  return `<details class="person-card" id="${attribute(personAnchor(person.id))}" style="--team:${color(teamName(person))}"><summary><span class="avatar">${avatar}</span><span class="identity"><strong>${escapeHtml(person.name)}</strong><span>${escapeHtml(role)}</span></span>${directReports.length > 0 ? `<span class="report-count" aria-label="${String(directReports.length)} direct reports">${String(directReports.length)}</span>` : ""}</summary><div class="person-details"><dl><div><dt>Team</dt><dd>${escapeHtml(teamName(person))}</dd></div><div><dt>Reports to</dt><dd>${managerValue}</dd></div>${directReports.length > 0 ? `<div><dt>Manages</dt><dd>${managesValue}</dd></div>` : ""}</dl><div class="links"><a href="mailto:${attribute(person.email)}" target="_blank" rel="noopener noreferrer">${escapeHtml(person.email)}</a>${person.githubProfile ? `<a href="${attribute(person.githubProfile.profileUrl)}" target="_blank" rel="noopener noreferrer">GitHub ↗</a>` : ""}${person.linkedinUrl ? `<a href="${attribute(person.linkedinUrl)}" target="_blank" rel="noopener noreferrer">LinkedIn ↗</a>` : ""}</div></div></details>`;
}

function personAnchor(id: string): string {
  return `person-${slug(id)}`;
}

function profileRow(
  person: ChartPerson,
  photos: ReadonlyMap<string, string>,
): string {
  const role = person.title || teamName(person);
  const photo = photos.get(person.id);
  const avatar = photo
    ? `<img src="${attribute(photo)}" alt="" loading="lazy" decoding="async">`
    : `<span aria-hidden="true">${escapeHtml(initials(person.name))}</span>`;
  const github = person.githubProfile
    ? `<a href="${attribute(person.githubProfile.profileUrl)}" target="_blank" rel="noopener noreferrer">@${escapeHtml(person.githubProfile.login)} ↗</a>`
    : '<span class="missing">Not added</span>';
  const linkedin = person.linkedinUrl
    ? `<a href="${attribute(person.linkedinUrl)}" target="_blank" rel="noopener noreferrer">View profile ↗</a>`
    : '<span class="missing">Not added</span>';
  return `<tr><th scope="row"><span class="table-person"><span class="table-avatar">${avatar}</span><span><strong>${escapeHtml(person.name)}</strong><small>${escapeHtml(person.email)}</small></span></span></th><td>${escapeHtml(role)}</td><td>${escapeHtml(teamName(person))}</td><td>${github}</td><td>${linkedin}</td></tr>`;
}

function initials(name: string): string {
  return name
    .split(/\s+/u)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toLocaleUpperCase("en-US") ?? "")
    .join("");
}

function slug(value: string): string {
  return value
    .toLocaleLowerCase("en-US")
    .replaceAll(/[^a-z0-9]+/gu, "-")
    .replaceAll(/^-|-$/gu, "");
}

function color(team: string): string {
  return DEPARTMENT_COLORS[team] ?? "#667085";
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function attribute(value: string): string {
  return escapeHtml(value);
}

function styles(): string {
  return `@font-face{font-family:"Nunito";src:url(data:font/ttf;base64,${NUNITO_REGULAR_BASE64}) format("truetype");font-style:normal;font-weight:400;font-display:swap}@font-face{font-family:"Nunito";src:url(data:font/ttf;base64,${NUNITO_SEMIBOLD_BASE64}) format("truetype");font-style:normal;font-weight:600 900;font-display:swap}:root{color-scheme:light;--ink:#231f20;--muted:#666666;--muted-2:#817b78;--detail:#4f4947;--line:#e8e1dc;--subtle-line:#f1ece8;--paper:#ffffff;--wash:#f6efe7;--hover:#fbfaf9;--switch-bg:rgba(255,255,255,.45);--accent:#6352a2;--accent-soft:rgba(99,82,162,.10);font-family:"Nunito",ui-rounded,"Avenir Next",Avenir,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}*{box-sizing:border-box}html{background:var(--wash);scroll-behavior:smooth}body{margin:0;color:var(--ink);background:var(--wash);-webkit-font-smoothing:antialiased}button,summary{font:inherit}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}main{width:min(1180px,100%);margin:auto;padding:clamp(18px,3vw,36px) clamp(14px,3vw,36px)}.toolbar{margin-bottom:18px;padding-bottom:14px;border-bottom:1px solid var(--line)}.view-switch{display:inline-flex;padding:3px;border:1px solid var(--line);border-radius:9px;background:var(--switch-bg)}.view-switch button{min-height:34px;padding:0 15px;border:0;border-radius:6px;color:var(--muted);background:transparent;font-size:12px;font-weight:700;cursor:pointer}.view-switch button[aria-selected=true]{color:var(--accent);background:var(--paper);box-shadow:0 1px 3px rgba(0,0,0,.10)}.view-switch button:focus-visible{outline:2px solid var(--accent);outline-offset:2px}.teams{display:block}.directory-section{margin-bottom:26px}.team-panel{padding-top:2px}.section-heading{display:flex;align-items:center;gap:8px;margin:0 0 9px;padding-bottom:7px;border-bottom:1px solid color-mix(in srgb,var(--team) 28%,var(--line))}.section-heading::before{width:5px;height:5px;border-radius:50%;background:var(--team);content:""}.section-heading h2{margin:0;font-size:13px;font-weight:700;letter-spacing:-.01em}.section-heading span{color:var(--muted);font-size:10px}.people-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));align-items:start;gap:7px}.person-card{min-width:0;scroll-margin-top:18px;border:1px solid var(--line);border-radius:8px;background:var(--paper);overflow:hidden}.person-card[open]{border-color:color-mix(in srgb,var(--accent) 40%,var(--line));box-shadow:0 5px 16px rgba(0,0,0,.10)}.person-card:target{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft),0 5px 16px rgba(0,0,0,.12)}.person-card summary{display:flex;min-height:66px;align-items:center;gap:9px;padding:9px;cursor:pointer;list-style:none;outline:none}.person-card summary::-webkit-details-marker{display:none}.person-card summary::after{content:"+";margin-left:0;color:var(--muted-2);font-size:15px;font-weight:400}.person-card[open] summary::after{content:"–"}.person-card summary:hover{background:var(--hover)}.person-card summary:focus-visible{box-shadow:inset 0 0 0 2px var(--accent)}.avatar,.table-avatar,.tree-avatar{display:grid;place-items:center;flex:0 0 auto;border-radius:50%;overflow:hidden;color:var(--accent);background:var(--accent-soft);font-size:10px;font-weight:800}.avatar{width:42px;height:42px}.avatar img,.table-avatar img,.tree-avatar img{width:100%;height:100%;object-fit:cover}.identity{display:flex;min-width:0;flex:1;flex-direction:column;gap:2px}.identity strong,.identity span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.identity strong{font-size:12px;font-weight:700;letter-spacing:-.01em}.identity span{color:var(--muted);font-size:10px}.report-count{display:grid;place-items:center;flex:0 0 auto;min-width:21px;height:21px;margin-left:auto;border-radius:50%;color:var(--accent);background:var(--accent-soft);font-size:9px;font-weight:800}.person-details{padding:0 11px 11px 60px;border-top:1px solid var(--subtle-line)}.person-details dl{margin:8px 0}.person-details dl div{display:grid;grid-template-columns:58px 1fr;gap:7px;padding:3px 0;font-size:10px;line-height:1.5}.person-details dt{color:var(--muted-2)}.person-details dd{margin:0;color:var(--detail)}.person-jump,.links a,.linkedin-view a{color:var(--accent);font-weight:600;text-decoration-thickness:1px;text-underline-offset:2px}.links{display:flex;flex-wrap:wrap;gap:8px 14px}.links a{font-size:10px}.hierarchy-roots,.hierarchy-roots ul{margin:0;padding:0;list-style:none}.hierarchy-roots{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));align-items:start;gap:14px}.hierarchy-roots ul{margin-left:19px;padding-left:19px;border-left:1px solid var(--line)}.hierarchy-roots li{position:relative;margin:7px 0}.hierarchy-roots ul>li::before{position:absolute;top:25px;left:-19px;width:15px;border-top:1px solid var(--line);content:""}.hierarchy-person{display:flex;min-height:51px;align-items:center;gap:9px;padding:7px 9px;border:1px solid var(--line);border-radius:8px;color:var(--ink);background:var(--paper);text-decoration:none}.hierarchy-person:hover{border-color:color-mix(in srgb,var(--accent) 35%,var(--line));background:var(--hover)}.hierarchy-person:focus-visible{outline:2px solid var(--accent);outline-offset:2px}.hierarchy-person>span:nth-child(2){display:flex;min-width:0;flex:1;flex-direction:column}.hierarchy-person strong,.hierarchy-person small{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.hierarchy-person strong{font-size:12px}.hierarchy-person small{color:var(--muted);font-size:9px}.tree-avatar{width:34px;height:34px}.tree-count{display:grid;place-items:center;width:21px;height:21px;border-radius:50%;color:var(--accent);background:var(--accent-soft);font-size:9px;font-weight:800}.linkedin-view{min-width:0}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:9px;background:var(--paper)}table{width:100%;border-collapse:collapse;font-size:12px;text-align:left}th,td{padding:10px 13px;border-bottom:1px solid var(--line);vertical-align:middle}thead th{position:sticky;top:0;z-index:1;color:var(--muted);background:var(--hover);font-size:9px;font-weight:800;letter-spacing:.06em;text-transform:uppercase}tbody tr:last-child th,tbody tr:last-child td{border-bottom:0}tbody tr:hover{background:var(--hover)}tbody th{font-weight:400}.table-person{display:flex;min-width:190px;align-items:center;gap:9px}.table-person>span:last-child{display:flex;min-width:0;flex-direction:column}.table-person strong{font-size:12px;font-weight:700}.table-person small{overflow:hidden;color:var(--muted);font-size:9px;font-weight:400;text-overflow:ellipsis;white-space:nowrap}.table-avatar{width:32px;height:32px}.missing{color:var(--muted-2);font-size:10px}[hidden]{display:none!important}footer{margin-top:8px;padding-top:14px;border-top:1px solid var(--line);color:var(--muted-2);font-size:9px}@media(prefers-color-scheme:dark){:root{color-scheme:dark;--ink:#f3efed;--muted:#aaa3a0;--muted-2:#8f8885;--detail:#cbc4c1;--line:#3a3534;--subtle-line:#302c2b;--paper:#211f20;--wash:#171516;--hover:#292627;--switch-bg:rgba(255,255,255,.04);--accent:#b7a4ff;--accent-soft:rgba(183,164,255,.13)}}@media(max-width:980px){.people-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.hierarchy-roots{grid-template-columns:1fr}}@media(max-width:480px){main{padding:14px 10px}.view-switch button{padding:0 10px}.people-grid{grid-template-columns:1fr}.directory-section{margin-bottom:22px}.person-card summary{min-height:62px}.person-details{padding-left:60px}.hierarchy-roots ul{margin-left:12px;padding-left:13px}.hierarchy-roots ul>li::before{left:-13px;width:10px}th,td{padding:9px 10px}.table-person{min-width:165px}}@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}`;
}

function script(): string {
  return `const teamsTab=document.getElementById("teams-tab");const hierarchyTab=document.getElementById("hierarchy-tab");const linkedinTab=document.getElementById("linkedin-tab");const teamsView=document.getElementById("teams-view");const hierarchyView=document.getElementById("hierarchy-view");const linkedinView=document.getElementById("linkedin-view");const tabs=[teamsTab,hierarchyTab,linkedinTab];const views={teams:teamsView,hierarchy:hierarchyView,linkedin:linkedinView};let activeView="teams";function setView(view,focus=false){activeView=view;for(const tab of tabs){const selected=tab.id===view+"-tab";tab.setAttribute("aria-selected",String(selected));tab.tabIndex=selected?0:-1}for(const [name,panel] of Object.entries(views))panel.hidden=name!==view;if(focus)document.getElementById(view+"-tab").focus()}teamsTab.addEventListener("click",()=>setView("teams"));hierarchyTab.addEventListener("click",()=>setView("hierarchy"));linkedinTab.addEventListener("click",()=>setView("linkedin"));for(const [index,tab] of tabs.entries())tab.addEventListener("keydown",event=>{if(!["ArrowLeft","ArrowRight","Home","End"].includes(event.key))return;event.preventDefault();const target=event.key==="Home"?0:event.key==="End"?tabs.length-1:event.key==="ArrowLeft"?(index-1+tabs.length)%tabs.length:(index+1)%tabs.length;setView(tabs[target].id.replace("-tab",""),true)});function openLinkedPerson(){const id=decodeURIComponent(location.hash.slice(1));if(!id)return;const target=document.getElementById(id);if(!(target instanceof HTMLDetailsElement))return;if(activeView!=="teams")setView("teams");target.open=true;requestAnimationFrame(()=>{target.scrollIntoView({block:"center"});target.querySelector("summary")?.focus({preventScroll:true})})}window.addEventListener("hashchange",openLinkedPerson);openLinkedPerson();`;
}
