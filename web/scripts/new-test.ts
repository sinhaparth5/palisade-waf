// bun run new:test <component|query|page> <path/to/Name.tsx> [route path]
// Writes Name.test.tsx next to it from test-templates/.
import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const [kind, file, route = "/"] = process.argv.slice(2);
const kinds = ["component", "query", "page"];
if (!kind || !kinds.includes(kind) || !file) {
  console.error(`usage: bun run new:test <${kinds.join("|")}> <src/features/x/Name.tsx> [route path for page]`);
  process.exit(2);
}
const name = basename(file).replace(/\.tsx?$/, "");
const out = join(dirname(file), `${name}.test.tsx`);
if (existsSync(out)) {
  console.error(`${out} already exists`);
  process.exit(1);
}
const templates = fileURLToPath(new URL("../test-templates/", import.meta.url));
const tmpl = await readFile(join(templates, `${kind}.test.tsx.tmpl`), "utf8");
await writeFile(out, tmpl.replaceAll("__Name__", name).replaceAll("__path__", route));
console.log(`wrote ${out}: replace the TODO queries and API routes with the real ones`);
