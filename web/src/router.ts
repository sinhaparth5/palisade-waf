import type { QueryClient } from "@tanstack/react-query";
import { createRouter, type RouterHistory } from "@tanstack/react-router";
import { ErrorScreen, NotFound } from "@/components/layout/Fallback";
import { boot } from "@/lib/boot";
import { routeTree } from "./routeTree.gen";

// One router setup for the app (main.tsx) and the tests (renderRoute).
// Palisade's screens are the defaults: a route without its own errorComponent
// falls back to these, not to its parent's.
export const createAppRouter = (queryClient: QueryClient, history?: RouterHistory) =>
  createRouter({
    routeTree,
    basepath: boot.admin,
    context: { queryClient },
    history,
    defaultErrorComponent: ErrorScreen,
    defaultNotFoundComponent: NotFound,
  });
