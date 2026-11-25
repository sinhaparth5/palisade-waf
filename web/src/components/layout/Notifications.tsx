import { useEffect } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { api } from "@/lib/api";
import { boot } from "@/lib/boot";

// The sidebar bell, as on the HTMX pages: unread blocked requests since the
// last "mark all as read", the six latest, and a toast per new block from the
// same SSE stream.
type Block = { time: string; ip: string; country: string; method: string; path: string; app: string; rule_id: number; action: string };
type Panel = { unread: number; blocks: Block[] };
type Live = { action: string; ip: string; country: string; method: string; path: string };

const key = ["notifications"];

// Same wording as the HTMX toasts (static/js/src/toast.js).
export function blockTitle(action: string) {
  const a = action.toLowerCase();
  if (a.startsWith("rate_limited")) return "Too Many Requests";
  if (a.includes("geo")) return "Country Blocked";
  if (a.includes("ip")) return "IP Address Blocked";
  return "Request Blocked";
}

const time = (iso: string) =>
  new Date(iso).toLocaleString("en-GB", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit" });

export function Notifications() {
  const qc = useQueryClient();
  const { data, isError, refetch } = useQuery({ queryKey: key, queryFn: () => api<Panel>("/api/notifications") });
  const seen = useMutation({
    mutationFn: () => api("/api/notifications/seen", { method: "POST" }),
    onSuccess: () => qc.setQueryData<Panel>(key, (p) => p && { ...p, unread: 0 }),
  });

  useEffect(() => {
    const stream = new EventSource(`${boot.admin}/api/notifications/stream`);
    stream.addEventListener("count", (e) => qc.setQueryData<Panel>(key, (p) => p && { ...p, unread: Number(e.data) }));
    stream.addEventListener("toast", (e) => {
      const b = JSON.parse(e.data) as Live;
      toast(blockTitle(b.action), { description: `${b.ip}${b.country ? ` · ${b.country}` : ""} — ${b.method || "GET"} ${b.path || "/"}` });
    });
    return () => stream.close();
  }, [qc]);

  const unread = data?.unread ?? 0;
  return (
    <Popover onOpenChange={(open) => open && void refetch()}>
      <PopoverTrigger
        aria-label={unread ? `Notifications, ${unread} unread` : "Notifications"}
        className="relative flex h-11 w-11 cursor-pointer items-center justify-center rounded-sm border border-side-line text-side-ink hover:bg-white/10 lg:h-9 lg:w-9"
      >
        <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-notification-03 text-[14px]" />
        {unread > 0 && (
          <span className="absolute -top-[5px] -right-[5px] flex h-[17px] min-w-[17px] items-center justify-center rounded-full border-2 border-side bg-danger px-[3px] font-mono text-[10px] font-bold text-white">
            {unread > 9 ? "9+" : unread}
          </span>
        )}
      </PopoverTrigger>
      <PopoverContent side="right" align="end" sideOffset={16} className="w-[340px] rounded-none border-edge bg-card p-3 text-ink">
        <div className="flex items-center justify-between px-[10px] pt-1 pb-2">
          <p className="font-mono text-[11px] font-medium uppercase tracking-[.08em] text-slate-500">Recent blocks</p>
          <button type="button" onClick={() => seen.mutate()} className="cursor-pointer font-mono text-[11px] uppercase tracking-[.06em] text-ink underline">
            Mark all as read
          </button>
        </div>
        {isError && (
          <p role="alert" className="p-4 text-center text-[13px] text-red-600">
            Couldn't load notifications.
          </p>
        )}
        {data?.blocks.length === 0 && <p className="p-4 text-center text-[13px] text-slate-500">No blocked requests yet.</p>}
        <ul>
          {data?.blocks.map((b, i) => (
            <li key={i} className="flex items-center gap-[10px] p-[10px]">
              <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-red-100">
                <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-cancel-circle text-[13px] text-red-600" />
              </span>
              <span className="min-w-0 flex-1">
                <span className="block truncate font-mono text-[13px] font-semibold text-slate-800">
                  {b.ip} <span className="font-normal text-slate-500">→ {b.path}</span>
                </span>
                <span className="block text-[11px] text-slate-500">
                  {b.app} · {time(b.time)}
                  {b.rule_id ? ` · rule #${b.rule_id}` : ""}
                </span>
              </span>
            </li>
          ))}
        </ul>
        <a href={`${boot.admin}/logs?status=blocked`} className="mt-1 block border-t border-edge p-2 text-center font-mono text-[11px] uppercase tracking-[.06em] text-ink no-underline">
          View all blocked →
        </a>
      </PopoverContent>
    </Popover>
  );
}
