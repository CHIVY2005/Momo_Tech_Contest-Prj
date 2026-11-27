import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const FRONTEND_ROOT = resolve(HERE, "..", "..", "..");
const SRC_ROOT = join(FRONTEND_ROOT, "src");

interface PackageManifest {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  license?: string | { type?: string };
}

const pkg = JSON.parse(
  readFileSync(join(FRONTEND_ROOT, "package.json"), "utf8"),
) as PackageManifest;

const ALLOWED = new Set(["MIT", "ISC", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "0BSD"]);
const BANNED = [/^gsap$/, /^@gsap\//, /react-bits/i, /^@hugeicons\//, /^three$/, /^ogl$/];

function readLicense(dep: string): string {
  const manifestPath = join(FRONTEND_ROOT, "node_modules", ...dep.split("/"), "package.json");
  if (!existsSync(manifestPath)) {
    return `NOT_INSTALLED(${dep})`;
  }
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as PackageManifest;
  const lic = manifest.license;
  if (typeof lic === "string") return lic;
  return lic?.type ?? "UNKNOWN";
}

function listSourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) {
      if (name === "__tests__") continue;
      out.push(...listSourceFiles(full));
    } else if (/\.(?:ts|tsx|css)$/.test(name)) {
      out.push(full);
    }
  }
  return out;
}

test("mọi runtime dependency có giấy phép permissive", () => {
  for (const dep of Object.keys(pkg.dependencies ?? {})) {
    const lic = readLicense(dep);
    assert.ok(ALLOWED.has(lic), `${dep} license ${lic}`);
  }
});

test("không có dependency bị cấm (GSAP / React Bits / WebGL)", () => {
  const all = [...Object.keys(pkg.dependencies ?? {}), ...Object.keys(pkg.devDependencies ?? {})];
  for (const dep of all) {
    assert.ok(!BANNED.some((re) => re.test(dep)), `banned dependency: ${dep}`);
  }
});

test("lenis và motion đã được khai báo", () => {
  assert.ok(pkg.dependencies?.lenis, "lenis missing");
  assert.ok(pkg.dependencies?.motion, "motion missing");
});

test("không có mã nguồn sao chép từ React Bits trong src/", () => {
  for (const file of listSourceFiles(SRC_ROOT)) {
    const text = readFileSync(file, "utf8");
    assert.ok(!/reactbits\.dev|David Haz/i.test(text), `React Bits marker found in ${file}`);
  }
});
