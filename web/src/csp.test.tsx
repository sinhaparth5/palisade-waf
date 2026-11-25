import { render, screen } from "@testing-library/react";
import { Dialog, Popover } from "radix-ui";
import { Command } from "cmdk";
import { setNonce } from "get-nonce";
import { Toaster, toast } from "sonner";
import { boot } from "@/lib/boot";

// The admin CSP blocks any <style> without this request's nonce
// (internal/ui/app.go). Libraries that inject one must carry it, or not inject.
test("no injected <style> lacks the CSP nonce", async () => {
  setNonce(boot.nonce);
  render(
    <>
      <Toaster />
      <Dialog.Root defaultOpen>
        <Dialog.Portal>
          <Dialog.Overlay />
          <Dialog.Content aria-describedby={undefined}>
            <Dialog.Title>t</Dialog.Title>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
      <Popover.Root defaultOpen>
        <Popover.Trigger>p</Popover.Trigger>
        <Popover.Portal>
          <Popover.Content>popover</Popover.Content>
        </Popover.Portal>
      </Popover.Root>
      <Command>
        <Command.Input />
        <Command.List>
          <Command.Item>item</Command.Item>
        </Command.List>
      </Command>
    </>,
  );
  toast("hello");
  await screen.findByText("hello");
  const styles = [...document.querySelectorAll("style")];
  expect(styles.length).toBeGreaterThan(0); // the overlay's scroll lock injects one
  for (const s of styles) expect(s.nonce || s.getAttribute("nonce")).toBe(boot.nonce);
});
