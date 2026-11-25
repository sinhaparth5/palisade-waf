import { createFileRoute } from "@tanstack/react-router";
import { CertificatesPage } from "@/features/certificates/CertificatesPage";

export const Route = createFileRoute("/certificates")({ component: CertificatesPage });
