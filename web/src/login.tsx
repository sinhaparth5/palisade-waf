import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { LoginPage } from "@/features/login/LoginPage";
import "./index.css";

createRoot(document.getElementById("palisade")!).render(
  <StrictMode>
    <LoginPage />
  </StrictMode>,
);
