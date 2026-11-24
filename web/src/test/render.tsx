import type { ReactElement, ReactNode } from "react";
import { render, type RenderOptions } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider, createMemoryHistory, createRouter } from "@tanstack/react-router";
import { boot } from "@/lib/boot";
import { routeTree } from "@/routeTree.gen";

// A fresh client per test: no cache shared between tests, no retries (an
// error state shows at once), errors not logged to the console.
export function testQueryClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
  });
}

// renderWithProviders renders one component with the app's providers.
// For a component that doesn't use router hooks (Link, useNavigate...);
// use renderRoute for pages.
export function renderWithProviders(ui: ReactElement, options: RenderOptions & { queryClient?: QueryClient } = {}) {
  const queryClient = options.queryClient ?? testQueryClient();
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  );
  return { user: userEvent.setup(), queryClient, ...render(ui, { wrapper, ...options }) };
}

// renderRoute renders the real app router at path ("/services/3"), the way a
// browser opening {admin}/app/services/3 would. Await it: the route loads first.
export async function renderRoute(path: string, { queryClient = testQueryClient() } = {}) {
  const basepath = `${boot.admin}/app`;
  const router = createRouter({
    routeTree,
    basepath,
    context: { queryClient },
    history: createMemoryHistory({ initialEntries: [basepath + path] }),
  });
  await router.load();
  const result = render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  );
  return { user: userEvent.setup(), router, queryClient, ...result };
}
