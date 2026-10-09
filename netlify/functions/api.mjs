import { Readable } from "node:stream";
import handler from "../../api/index.mjs";

export default async function api(request) {
  const req = request.body ? Readable.fromWeb(request.body) : Readable.from([]);
  req.method = request.method;
  req.url = request.url;
  req.headers = Object.fromEntries(request.headers);
  const headers = new Headers();
  let body = "";
  const res = {
    statusCode: 200,
    setHeader(name, value) { headers.set(name, value); },
    end(value) { body = value; },
  };
  await handler(req, res);
  return new Response(body, { status: res.statusCode, headers });
}

export const config = { path: "/api/*" };
