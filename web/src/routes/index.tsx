import { createFileRoute } from "@tanstack/react-router";
import { Page, PageHeader } from "@/components/layout/Page";

export const Route = createFileRoute("/")({
  component: () => (
    <Page>
      <PageHeader title="Dashboard" />
    </Page>
  ),
});
