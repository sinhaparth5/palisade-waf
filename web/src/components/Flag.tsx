import { cn } from "@/lib/utils";

// A country flag from the vendored flag-icons CSS (ISO alpha-2 codes only).
export function Flag({ code, className }: { code: string; className?: string }) {
  if (!/^[a-z]{2}$/i.test(code)) return null;
  return <span aria-hidden className={cn(`fi fi-${code.toLowerCase()} inline-block h-3 w-4 shrink-0 bg-cover`, className)} />;
}
