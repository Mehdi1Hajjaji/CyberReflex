import { getPrisma } from "./prisma";
import type { ScanResult } from "./scan/types";

export async function saveScanResult(
  result: ScanResult,
  requestIp?: string | null,
) {
  const prisma = getPrisma();

  if (!prisma) {
    return false;
  }

  try {
    await prisma.scan.create({
      data: {
        url: result.normalizedUrl,
        grade: result.grade,
        score: result.score,
        results: JSON.parse(JSON.stringify(result)),
        aiSummary: result.aiSummary,
        ipAddress: requestIp ?? undefined,
      },
    });

    return true;
  } catch {
    return false;
  }
}
