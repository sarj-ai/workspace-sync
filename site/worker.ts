interface Environment {
  readonly ASSETS: { fetch(request: Request): Promise<Response> };
}

const base = "/engineering/projects/workspace-sync";
const oldBase = "/projects/workspace-sync";

const worker = {
  fetch(
    request: Request,
    environment: Environment,
  ): Promise<Response> | Response {
    const url = new URL(request.url);
    const legacy =
      url.hostname === "engineering.sarj.ai" &&
      (url.pathname === oldBase || url.pathname.startsWith(`${oldBase}/`));
    if (legacy) {
      url.hostname = "sarj.ai";
      url.pathname = `${base}${url.pathname.slice(oldBase.length)}`;
    }
    if (
      url.hostname !== "sarj.ai" ||
      (url.pathname !== base && !url.pathname.startsWith(`${base}/`))
    )
      return new Response(null, { status: 404 });
    if (url.pathname === base) url.pathname += "/";
    if (legacy || new URL(request.url).pathname === base)
      return Response.redirect(url.href, 308);
    if (request.method !== "GET" && request.method !== "HEAD")
      return new Response(null, {
        status: 405,
        headers: { allow: "GET, HEAD" },
      });
    return environment.ASSETS.fetch(request);
  },
} as const;

export default worker;
