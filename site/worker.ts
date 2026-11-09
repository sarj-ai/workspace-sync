interface Environment {
  readonly ASSETS: { fetch(request: Request): Promise<Response> };
}

export default {
  fetch(
    request: Request,
    environment: Environment,
  ): Promise<Response> | Response {
    const url = new URL(request.url);
    if (url.pathname === "/projects/workspace-sync") {
      url.pathname += "/";
      return Response.redirect(url.href, 308);
    }
    if (!url.pathname.startsWith("/projects/workspace-sync/"))
      return new Response(null, { status: 404 });
    if (request.method !== "GET" && request.method !== "HEAD")
      return new Response(null, {
        status: 405,
        headers: { allow: "GET, HEAD" },
      });
    return environment.ASSETS.fetch(request);
  },
};
