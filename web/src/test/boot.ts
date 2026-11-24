import { boot, type Role } from "@/lib/boot";

const initial = { ...boot };

// setBoot changes what Go "rendered" for one test (role, demo, ...).
// setup.ts resets it after every test.
export function setBoot(values: Partial<typeof boot>) {
  Object.assign(boot, values);
}

export const asRole = (role: Role) => setBoot({ role });

export function resetBoot() {
  Object.assign(boot, initial);
}
