import { useEffect, useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { api } from "@/lib/api";

// Top bar search (issue #225): pages, cards and live records, from the same
// {admin}/search the HTMX pages use (JSON here). Ctrl/Cmd+K or / opens it.
type Group = { label: string; icon: string; hits: { title: string; detail: string; url: string }[] };

export function Search() {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [term, setTerm] = useState("");
  useEffect(() => {
    const t = setTimeout(() => setTerm(q.trim()), 150);
    return () => clearTimeout(t);
  }, [q]);

  const { data, isError, isPlaceholderData } = useQuery({
    queryKey: ["search", term],
    queryFn: () => api<Group[]>(`/search?q=${encodeURIComponent(term)}`),
    enabled: open && term !== "",
    placeholderData: keepPreviousData,
  });

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName) || t.isContentEditable;
      if ((e.key === "k" && (e.ctrlKey || e.metaKey)) || (e.key === "/" && !typing)) {
        e.preventDefault();
        setOpen(true);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  return (
    <>
      <button
        type="button"
        aria-label="Search"
        aria-keyshortcuts="Control+K Meta+K /"
        onClick={() => setOpen(true)}
        className="flex h-11 items-center gap-2 rounded-sm border border-edge px-3 text-slate-600 hover:bg-surface hover:text-ink sm:h-9"
      >
        <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-search-01 text-base" />
        <span className="hidden sm:inline">Search</span>
        <kbd className="hidden font-mono text-[11px] text-slate-500 md:inline">Ctrl K</kbd>
      </button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent
          showCloseButton={false}
          className="top-[10vh] w-[min(640px,calc(100%-2rem))] max-w-none translate-y-0 gap-0 rounded-none border-edge bg-canvas p-0 sm:max-w-none"
        >
          <DialogTitle className="sr-only">Search</DialogTitle>
          <DialogDescription className="sr-only">Search pages, services and rules</DialogDescription>
          {/* The server ranks and filters; cmdk only handles the keyboard. */}
          <Command shouldFilter={false} className="rounded-none bg-transparent">
            <CommandInput value={q} onValueChange={setQ} placeholder="Search pages, services, rules…" className="h-12 text-[15px]" />
            <CommandList className="max-h-[60vh]">
              {isError && (
                <p role="alert" className="px-4 py-6 text-center text-red-600">
                  Search failed. Try again.
                </p>
              )}
              {term && data && !isPlaceholderData && <CommandEmpty className="px-4 py-6 text-center text-slate-500">No results for “{term}”.</CommandEmpty>}
              {term &&
                data?.map((g) => (
                  <CommandGroup
                    key={g.label}
                    heading={
                      <span className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-[.08em] text-slate-500">
                        <i aria-hidden className={`hgi hgi-stroke hgi-rounded ${g.icon}`} />
                        {g.label}
                      </span>
                    }
                  >
                    {g.hits.map((h) => (
                      <CommandItem
                        key={g.label + h.url + h.title}
                        value={g.label + h.url + h.title}
                        onSelect={() => window.location.assign(h.url)}
                        className="flex items-baseline justify-between gap-4 rounded-none px-4 py-2"
                      >
                        <span className="min-w-0 truncate text-ink">{h.title}</span>
                        <span className="shrink-0 truncate font-mono text-[12px] text-slate-500">{h.detail}</span>
                      </CommandItem>
                    ))}
                  </CommandGroup>
                ))}
            </CommandList>
          </Command>
        </DialogContent>
      </Dialog>
    </>
  );
}
