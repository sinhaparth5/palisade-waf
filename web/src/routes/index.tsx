import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/")({
  component: () => (
    <main className="p-8">
      <h1 className="text-xl">Palisade</h1>
      <p className="text-muted-foreground mt-2">React admin scaffold.</p>
    </main>
  ),
});
