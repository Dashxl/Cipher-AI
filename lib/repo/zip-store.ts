import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

const baseDir = path.join(os.tmpdir(), "cipher-ai-zips");

// Persistente “best effort” (mem + /tmp). Para demo va perfecto.
const g = globalThis as unknown as { __cipherZipMem?: Map<string, Buffer> };
const mem = (g.__cipherZipMem ??= new Map<string, Buffer>());

export async function saveZip(id: string, buf: Buffer) {
  mem.set(id, buf);
  await fs.mkdir(baseDir, { recursive: true });
  await fs.writeFile(path.join(baseDir, `${id}.zip`), buf);
}

export async function loadZip(id: string): Promise<Buffer> {
  const fromMem = mem.get(id);
  if (fromMem) return fromMem;
  return await fs.readFile(path.join(baseDir, `${id}.zip`));
}
