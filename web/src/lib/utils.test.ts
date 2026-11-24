import { cn } from "./utils";

it("cn merges classes, later Tailwind utilities winning", () => {
  expect(cn("p-2 text-sm", false && "hidden", "p-4")).toBe("text-sm p-4");
});
