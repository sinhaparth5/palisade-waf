import type { ReactNode } from "react";
import { ArtHero } from "@/components/Art";
import { Page, PageHeader, labelMono } from "@/components/layout/Page";
import { btn } from "@/features/rules/shared";
import { boot, can } from "@/lib/boot";
import { cn } from "@/lib/utils";
import { CredentialsCard, DevicesCard, PasskeysCard, TwoFactorCard } from "./Account";
import { AuditCard, EmailCard, WebhookCard } from "./Alerts";
import { useAccount, useAlerts, useProtection, useTeam } from "./api";
import { BotCard, InfraCards, RateLimitCard, TrustedIPsCard, VarnishCard } from "./Protection";
import { APIKeysCard, SSOCard, UsersCard } from "./Team";

// Settings (issue #355), grouped as the HTMX page was: account & access,
// protection, infrastructure, alerts, activity. A role sees only the
// sections it can use; the server enforces the same roles on every route.

export function SettingsPage() {
  const owner = can("owner");
  const sections = [
    { id: "access", title: "Account & access" },
    ...(owner ? [{ id: "team", title: "Users & API keys" }] : []),
    { id: "protection", title: "Protection" },
    { id: "infrastructure", title: "Infrastructure" },
    ...(owner ? [{ id: "alerts", title: "Alerts & integrations" }] : []),
    { id: "activity", title: "Activity" },
  ];
  return (
    <Page>
      <PageHeader title="Settings" />
      <ArtHero art="console" eyebrow="System control" title="Who gets in, what is enforced, where alerts go.">
        <p className="max-w-[56ch] text-[14px] leading-relaxed text-slate-600">
          Accounts and sign-in, global protection defaults, the cache and backups, alert destinations and the record of every change. Each section saves on its own and applies without a restart.
        </p>
        {boot.pro && (
          <a href={`${boot.admin}/settings/pro`} className={cn(btn, "self-start")}>
            <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-license text-base" />
            Palisade Pro settings
          </a>
        )}
      </ArtHero>
      <nav aria-label="Settings sections" className="flex flex-wrap gap-2">
        {sections.map((s) => (
          <a key={s.id} href={`#settings-${s.id}`} className="flex min-h-10 items-center border border-edge px-4 font-mono text-[12px] uppercase tracking-[.04em] text-ink no-underline hover:bg-surface">
            {s.title}
          </a>
        ))}
      </nav>
      <Section id="access" title="Account & access" copy="Who can sign in, and how.">
        <AccountSection />
      </Section>
      {owner && (
        <Section id="team" title="Users & API keys" copy="Who else can sign in, single sign-on, and keys for the REST API. Owners only.">
          <TeamSection />
        </Section>
      )}
      <ProtectionSections />
      {owner && (
        <Section id="alerts" title="Alerts & integrations" copy="Where security events and reports are sent. Owners only.">
          <AlertsSection />
        </Section>
      )}
      <Section id="activity" title="Activity" copy="Every change made from this dashboard or the REST API.">
        <AuditCard />
      </Section>
    </Page>
  );
}

export function Section({ id, title, copy, children }: { id: string; title: string; copy: string; children: ReactNode }) {
  return (
    <section id={`settings-${id}`} aria-labelledby={`settings-${id}-title`} className="flex scroll-mt-20 flex-col gap-4">
      <div>
        <h2 id={`settings-${id}-title`} className="font-mono text-[16px] font-medium uppercase tracking-[.04em] text-ink">
          {title}
        </h2>
        <p className="text-[13px] text-slate-500">{copy}</p>
      </div>
      {children}
    </section>
  );
}

// Loaded is a section's read: a failed one says so, never an empty form.
export function Loaded<T>({ q, what, children }: { q: { data?: T; isError: boolean }; what: string; children: (d: T) => ReactNode }) {
  if (q.isError)
    return (
      <p role="alert" className="text-red-600">
        Couldn't load {what}. Reload to try again.
      </p>
    );
  if (!q.data) return <p className={cn(labelMono, "py-10 text-center")}>Loading…</p>;
  return <>{children(q.data)}</>;
}

function AccountSection() {
  const q = useAccount();
  return (
    <Loaded q={q} what="your account">
      {(a) => (
        <>
          <div className="grid grid-cols-1 items-start gap-6 lg:grid-cols-2">
            <CredentialsCard email={a.email} />
            <div className="flex min-w-0 flex-col gap-6">
              <TwoFactorCard on={a.totp} />
              <PasskeysCard a={a} />
            </div>
          </div>
          <DevicesCard a={a} />
        </>
      )}
    </Loaded>
  );
}

function TeamSection() {
  const q = useTeam();
  return (
    <Loaded q={q} what="users and API keys">
      {(t) => (
        <>
          <UsersCard t={t} />
          <div className="grid grid-cols-1 items-start gap-6 lg:grid-cols-2">
            <SSOCard key={`${t.sso.issuer}|${t.sso.client_id}|${t.sso.group}`} t={t} />
            <APIKeysCard t={t} />
          </div>
        </>
      )}
    </Loaded>
  );
}

// Protection and Infrastructure share one read.
function ProtectionSections() {
  const q = useProtection();
  const body = (children: (p: NonNullable<typeof q.data>) => ReactNode) => (
    <Loaded q={q} what="these settings">
      {children}
    </Loaded>
  );
  return (
    <>
      <Section id="protection" title="Protection" copy="Global bot and rate-limit defaults, and IPs that are never blocked.">
        {body((p) => (
          <>
            <div className="grid grid-cols-1 items-start gap-6 lg:grid-cols-2">
              <BotCard key={JSON.stringify(p.bot)} v={p.bot} />
              <RateLimitCard key={JSON.stringify(p.rate_limit)} v={p.rate_limit} />
            </div>
            <TrustedIPsCard key={p.trusted_ips.join()} ips={p.trusted_ips} />
          </>
        ))}
      </Section>
      <Section id="infrastructure" title="Infrastructure" copy="Cache, the database and rule reloads.">
        {body((p) => (
          <VarnishCard key={JSON.stringify(p.varnish)} v={p.varnish} />
        ))}
        <InfraCards />
      </Section>
    </>
  );
}

function AlertsSection() {
  const q = useAlerts();
  return (
    <Loaded q={q} what="the alert settings">
      {(a) => (
        <div className="grid grid-cols-1 items-start gap-6 lg:grid-cols-2">
          <WebhookCard key={JSON.stringify(a.webhook)} v={a.webhook} />
          <EmailCard key={JSON.stringify(a.email)} v={a.email} />
        </div>
      )}
    </Loaded>
  );
}
