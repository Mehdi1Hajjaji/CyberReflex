import { NextResponse } from "next/server";
import { z } from "zod";
import { saveScanResult } from "@/lib/save-scan";
import { runSecurityScan } from "@/lib/scan/report";

export const runtime = "nodejs";

const requestSchema = z.object({
  url: z.string().trim().min(1).max(2048),
});

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const parsed = requestSchema.safeParse(body);

    if (!parsed.success) {
      return NextResponse.json(
        {
          error: "Enter a valid URL or hostname to scan.",
        },
        {
          status: 400,
        },
      );
    }

    const scan = await runSecurityScan(parsed.data.url);
    const requestIp =
      request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
      request.headers.get("x-real-ip");
    const stored = await saveScanResult(scan, requestIp);

    return NextResponse.json({
      ...scan,
      stored,
    });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "The scan failed unexpectedly.";
    const status =
      message.includes("Invalid URL") || message.includes("supported")
        ? 400
        : 500;

    return NextResponse.json(
      {
        error: message,
      },
      {
        status,
      },
    );
  }
}
