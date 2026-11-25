import { useMemo, useState } from "react";
import { Flag } from "@/components/Flag";
import { Command, CommandEmpty, CommandInput, CommandItem, CommandList } from "@/components/ui/command";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { cn } from "@/lib/utils";
import { field } from "./shared";

// ISO 3166-1 alpha-2, the codes GeoIP answers with. Names come from the
// browser (Intl.DisplayNames), so nothing here needs translating.
const codes =
  "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS XK YE YT ZA ZM ZW".split(" ");

let names: Intl.DisplayNames | undefined;
export function countryName(code: string) {
  try {
    names ??= new Intl.DisplayNames(["en"], { type: "region" });
    return names.of(code) ?? code;
  } catch {
    return code;
  }
}

// CountryPicker picks any number of countries from a searchable list
// (name or code). The chosen ones show as chips under the button.
export function CountryPicker({ value, onChange, invalid }: { value: string[]; onChange: (codes: string[]) => void; invalid?: boolean }) {
  const [open, setOpen] = useState(false);
  const all = useMemo(() => codes.map((c) => ({ code: c, name: countryName(c) })).sort((a, b) => a.name.localeCompare(b.name)), []);
  const toggle = (c: string) => onChange(value.includes(c) ? value.filter((x) => x !== c) : [...value, c]);
  return (
    <div className="flex flex-col gap-2">
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <button type="button" aria-invalid={invalid || undefined} className={cn(field, "flex items-center justify-between gap-2 text-left")}>
            <span className={value.length ? "text-ink" : "text-slate-500"}>{value.length ? `${value.length} selected` : "Choose countries…"}</span>
            <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-arrow-down-01 text-[13px]" />
          </button>
        </PopoverTrigger>
        <PopoverContent align="start" className="w-[min(320px,90vw)] rounded-none border-edge bg-card p-0">
          <Command className="rounded-none bg-transparent">
            <CommandInput placeholder="Search countries…" />
            <CommandList className="max-h-72">
              <CommandEmpty>No country matches.</CommandEmpty>
              {all.map(({ code, name }) => (
                <CommandItem key={code} value={`${name} ${code}`} onSelect={() => toggle(code)} className="gap-2">
                  <Flag code={code} />
                  <span className="flex-1 truncate">{name}</span>
                  <span className="font-mono text-[11px] text-slate-500">{code}</span>
                  <i aria-hidden className={cn("hgi hgi-stroke hgi-rounded hgi-tick-02 text-[13px]", !value.includes(code) && "invisible")} />
                </CommandItem>
              ))}
            </CommandList>
          </Command>
        </PopoverContent>
      </Popover>
      {value.length > 0 && (
        <ul aria-label="Chosen countries" className="flex flex-wrap gap-2">
          {value.map((c) => (
            <li key={c}>
              <button type="button" onClick={() => toggle(c)} aria-label={`Remove ${countryName(c)}`} className="flex items-center gap-[6px] rounded-sm border border-edge px-2 py-1 font-mono text-[12px] text-ink hover:bg-surface">
                <Flag code={c} />
                {c}
                <i aria-hidden className="hgi hgi-stroke hgi-rounded hgi-cancel-01 text-[11px]" />
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
