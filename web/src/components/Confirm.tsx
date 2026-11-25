import { useState } from "react";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle } from "@/components/ui/dialog";
import { btn } from "@/features/rules/shared";
import { cn } from "@/lib/utils";

// useConfirm asks before a change that can't be taken back in one click:
// render the returned dialog once, call ask() from any button.
export type Ask = { title: string; body: string; label: string; run: () => void };

export function useConfirm() {
  const [ask, setAsk] = useState<Ask | null>(null);
  const dialog = (
    <Dialog open={ask !== null} onOpenChange={(open) => !open && setAsk(null)}>
      <DialogContent className="rounded-none border-edge bg-canvas sm:max-w-md">
        <DialogTitle className="text-[16px] text-ink">{ask?.title}</DialogTitle>
        <DialogDescription className="text-[13px] text-slate-600">{ask?.body}</DialogDescription>
        <DialogFooter>
          <button type="button" onClick={() => setAsk(null)} className={btn}>
            Cancel
          </button>
          <button
            type="button"
            onClick={() => {
              ask!.run();
              setAsk(null);
            }}
            className={cn(btn, "border-red-600 bg-red-600 text-white hover:bg-red-700")}
          >
            {ask?.label}
          </button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
  return [dialog, setAsk] as const;
}
