import { screen } from "@testing-library/react";
import { renderWithProviders } from "@/test/render";
import { Card, FormRow, Grid, Page, PageHeader } from "./Page";

describe("layout primitives", () => {
  it("renders a page header with breadcrumb, title, tab title and actions", () => {
    renderWithProviders(
      <Page>
        <PageHeader title="Services" actions={<button>Add</button>} />
      </Page>,
    );
    expect(screen.getByRole("heading", { level: 1, name: "Services" })).toBeInTheDocument();
    expect(screen.getByText("Admin / Services")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add" })).toBeInTheDocument();
    expect(document.title).toBe("Palisade · Services");
  });

  it("fills a card's header, body and footer slots", () => {
    renderWithProviders(
      <Grid cols={3}>
        <Card cat="Routing" title="Backends" action={<button>Edit</button>} footer={<button>Save</button>}>
          body
        </Card>
        <Card>bare</Card>
      </Grid>,
    );
    expect(screen.getByRole("heading", { level: 2, name: "Backends" })).toBeInTheDocument();
    expect(screen.getByText("Routing")).toBeInTheDocument();
    expect(screen.getByText("bare").parentElement?.children).toHaveLength(1); // no header or footer
  });

  it("ties label, help and error to the control", () => {
    renderWithProviders(
      <>
        <FormRow label="Host" help="Comma separated" error="Already in use">
          <input />
        </FormRow>
        <FormRow label="Port">
          <input />
        </FormRow>
      </>,
    );
    const host = screen.getByLabelText("Host");
    expect(host).toHaveAccessibleDescription("Comma separated Already in use");
    expect(host).toHaveAttribute("aria-invalid", "true");
    const port = screen.getByLabelText("Port");
    expect(port).not.toHaveAttribute("aria-describedby");
    expect(port).not.toHaveAttribute("aria-invalid");
  });
});
