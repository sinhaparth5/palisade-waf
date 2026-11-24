import { boot } from "@/lib/boot";

// Palisade's own not-found and error screens, in place of the router's
// defaults, so a bad link or a crash still looks like Palisade.

function Screen({ code, title, children }: { code: string; title: string; children: React.ReactNode }) {
  return (
    <main className="flex min-h-dvh items-center justify-center bg-paper p-6 text-ink">
      <section className="w-full max-w-md border border-edge bg-card p-8">
        <p className="font-mono text-[11px] font-medium uppercase tracking-[.08em] text-muted">{code}</p>
        <h1 className="mt-2 text-xl">{title}</h1>
        <div className="mt-3 text-sm text-slate-600">{children}</div>
        {/* A full load, not a client link: after a crash, start from clean state. */}
        <a href={`${boot.admin}/app/`} className="mt-6 inline-block font-mono text-xs uppercase tracking-[.06em] underline underline-offset-4">
          Back to dashboard
        </a>
      </section>
    </main>
  );
}

export function NotFound() {
  return (
    <Screen code="404" title="Page not found">
      Nothing lives at this address in the admin.
    </Screen>
  );
}

// The message stays out of the page: it can carry internals. The console has it.
export function ErrorScreen({ error }: { error: unknown }) {
  console.error(error);
  return (
    <Screen code="Error" title="Something broke on this page">
      <p role="alert">Reload to try again. If it keeps happening, check the server log.</p>
    </Screen>
  );
}
