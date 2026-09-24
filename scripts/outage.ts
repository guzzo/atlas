import { readFile } from 'node:fs/promises';
import { http, PassportError } from '../sdk/wire.js';
const evidence = JSON.parse(
  await readFile(`${process.env.LOCAL_DIR ?? '.local'}/reports/last-evidence.json`, 'utf8'),
);
try {
  await http(`${process.env.GLOBEX_URL ?? 'http://127.0.0.1:8081'}/v0/verify`, evidence);
  throw Error('Registry outage was unexpectedly allowed');
} catch (error) {
  if (error instanceof PassportError && error.code === 'unavailable') {
    console.log('PASS  Globex fails closed while the registry is stopped');
  } else throw error;
}
