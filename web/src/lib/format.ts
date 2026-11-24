// Formatting shared by the request tables (Dashboard, Logs), matching the
// HTMX templates' fmtTime/fmtDur and status dots.

const pad = (n: number) => String(n).padStart(2, "0");

// "24 Nov 16:53:31", in the browser's time zone.
export function fmtTime(t: string | number) {
  const d = new Date(t);
  return `${pad(d.getDate())} ${d.toLocaleString("en", { month: "short" })} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export const statusDot = (status: number) =>
  status >= 500 ? "bg-danger" : status >= 400 ? "bg-warning" : status >= 300 ? "bg-info" : "bg-success";

// A request log row as storage.LogRow encodes it (the /api/v1 shape).
export type LogRow = {
  ID: number;
  Timestamp: string;
  AppName: string;
  RealIP: string;
  Country: string;
  Method: string;
  Host: string;
  Path: string;
  Status: number;
  Blocked: boolean;
  RuleID: number;
  Action: string;
  UserAgent: string;
  Duration: number;
};
