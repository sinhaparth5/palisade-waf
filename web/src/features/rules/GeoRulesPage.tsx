import { useState, type FormEvent } from "react";
import { toast } from "sonner";
import { Card, Page, PageHeader, labelMono } from "@/components/layout/Page";
import { Flag } from "@/components/Flag";
import { can } from "@/lib/boot";
import { fmtTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import { useGeoRules, useRemove, useWrite, type GeoRule } from "./api";
import { CountryPicker, countryName } from "./CountryPicker";
import { FormError, Overview, RuleBadge, RuleList, ScopeAction, fieldError, help, primary, tag } from "./shared";

export function GeoRulesPage() {
  const { data, isError } = useGeoRules();
  const remove = useRemove("geo-rules");
  const block = data?.filter((r) => r.RuleType === "block").length ?? 0;
  return (
    <Page>
      <PageHeader title="Geo Rules" />
      {can("admin") && <AddGeoRules />}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        {data && <Overview block={block} allow={data.length - block} what="countries" />}
        <div className="border border-amber-300 bg-amber-50 px-5 py-4">
          <p className="mb-1 flex items-center gap-2 text-[13px] font-semibold text-amber-800">
            <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-earth text-base text-amber-600" />
            GeoIP database bundled
          </p>
          <p className="text-[12px] leading-normal text-amber-800">
            The binary includes MaxMind GeoLite2 Country data. Pass <code className="bg-black/[.06] px-[5px] py-px font-mono text-[11px]">--geo-db</code> only when overriding it with a newer .mmdb file.
          </p>
        </div>
      </div>
      <Card cat="Firewall" title="Active Geo Rules" action={data && <span className={cn(tag, "text-slate-600")}>{data.length} rules</span>}>
        {isError ? (
          <p role="alert" className="py-6 text-red-600">
            Couldn't load the geo rules. Reload to try again.
          </p>
        ) : !data ? (
          <p className={cn(labelMono, "py-10 text-center")}>Loading…</p>
        ) : (
          <RuleList<GeoRule>
            rows={data}
            id={(r) => r.ID}
            label={(r) => countryName(r.CountryCode)}
            empty="No geo rules yet"
            remove={remove}
            row={(r) => (
              <>
                <Flag code={r.CountryCode} className="h-10 w-10 rounded-full" />
                <div className="min-w-0 flex-1">
                  <p className="font-mono text-[14px] font-bold tracking-[.08em] text-ink">
                    {r.CountryCode} <span className="font-sans font-normal tracking-normal text-slate-600">{countryName(r.CountryCode)}</span>
                  </p>
                  <p className="truncate text-[12px] text-slate-500">
                    {r.AppName || "Global"} · {fmtTime(r.CreatedAt)}
                  </p>
                </div>
                <RuleBadge type={r.RuleType} />
              </>
            )}
          />
        )}
      </Card>
    </Page>
  );
}

function AddGeoRules() {
  const add = useWrite<{ country_code: string[]; app_name: string; rule_type: string }>("geo-rules", "/api/geo-rules");
  const [picked, setPicked] = useState<string[]>([]);
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    add.mutate(
      { country_code: picked, app_name: String(f.get("app_name")), rule_type: String(f.get("rule_type")) },
      {
        onSuccess: (res) => {
          toast.success(res.added === 1 ? "Rule added." : `${res.added} rules added.`);
          setPicked([]);
        },
      },
    );
  };
  const codeErr = fieldError(add.error, "country_code");
  return (
    <Card title="Add Geo Rules">
      <form onSubmit={submit} className="grid grid-cols-1 items-start gap-4 md:grid-cols-2 lg:grid-cols-[1.4fr_1fr_auto_auto]">
        <div className="min-w-0">
          <span className={cn(labelMono, "mb-[6px] block")}>Countries</span>
          <CountryPicker value={picked} onChange={setPicked} invalid={!!codeErr} />
          {codeErr && <span className="mt-1 block text-xs text-red-600">{codeErr}</span>}
        </div>
        <ScopeAction error={add.error} />
        <button type="submit" disabled={add.isPending || picked.length === 0} className={cn(primary, "lg:mt-[22px]")}>
          <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-add-circle text-sm" />
          Add
        </button>
      </form>
      <FormError error={add.error} fields={["country_code", "app_name", "rule_type"]} />
      <p className={cn(help, "mt-5 border-t border-line pt-4")}>Per-app rules take priority over global ones. Allow rules bypass every other block.</p>
    </Card>
  );
}
