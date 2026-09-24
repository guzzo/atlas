import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { ZodError } from 'zod';
import { PassportError, canonical, strictJSON } from '../../sdk/wire.js';

export async function body(req: IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 128 * 1024) throw new PassportError('invalid_request', 413);
    chunks.push(Buffer.from(chunk));
  }
  return strictJSON(Buffer.concat(chunks).toString('utf8'));
}
export function send(res: ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(canonical(data));
}
export function serve(
  port: number,
  handler: (req: IncomingMessage, res: ServerResponse) => Promise<void>,
): void {
  const server = createServer(async (req, res) => {
    try {
      await handler(req, res);
    } catch (error) {
      const e =
        error instanceof PassportError
          ? error
          : error instanceof ZodError
            ? new PassportError('invalid_request', 400)
            : new PassportError('unavailable', 503);
      send(res, e.status, { decision: 'deny', code: e.code });
      if (!(error instanceof PassportError) && !(error instanceof ZodError))
        console.error('request failed:', error instanceof Error ? error.name : 'unknown');
    }
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 5000;
  server.maxHeadersCount = 50;
  server.listen(port, '0.0.0.0', () => console.error(`HTTP service ready on ${port}`));
  for (const signal of ['SIGINT', 'SIGTERM'])
    process.on(signal, () => {
      server.close(() => process.exit(0));
      setTimeout(() => process.exit(1), 5000).unref();
    });
}
