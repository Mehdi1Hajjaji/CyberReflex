import { headers } from "next/headers";
import { notFound } from "next/navigation";
import { ScanResults, type SavedScanPayload } from "@/components/scan-results";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type PageProps = {
  params: Promise<{ id: string }>;
};

export default async function ScanResultPage({ params }: PageProps) {
  const { id } = await params;
  const scan = await fetchSavedScan(id);

  if (!scan) {
    notFound();
  }

  return <ScanResults scan={scan} />;
}

async function fetchSavedScan(id: string): Promise<SavedScanPayload | null> {
  const headersList = await headers();
  const host = headersList.get("host");

  if (!host) {
    return null;
  }

  const protocol = headersList.get("x-forwarded-proto") ?? "http";
  const response = await fetch(`${protocol}://${host}/api/scan/${id}`, {
    cache: "no-store",
  });

  if (response.status === 404 || response.status === 400) {
    return null;
  }

  if (!response.ok) {
    throw new Error("Saved scan storage is currently unavailable.");
  }

  return (await response.json()) as SavedScanPayload;
}

