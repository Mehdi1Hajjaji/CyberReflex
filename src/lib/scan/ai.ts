import OpenAI from "openai";
import type { ScanCategory } from "./types";

type SummaryInput = {
  hostname: string;
  score: number;
  grade: string;
  categories: ScanCategory[];
};

export async function generateAiSummary(input: SummaryInput) {
  const fallback = buildFallbackSummary(input);

  if (!process.env.OPENAI_API_KEY) {
    return {
      text: fallback,
      aiEnhanced: false,
    };
  }

  try {
    const client = new OpenAI({
      apiKey: process.env.OPENAI_API_KEY,
    });

    const payload = {
      hostname: input.hostname,
      score: input.score,
      grade: input.grade,
      categories: input.categories.map((category) => ({
        label: category.label,
        status: category.status,
        summary: category.summary,
        findings: category.findings
          .filter((finding) => finding.status !== "pass")
          .map((finding) => ({
            title: finding.title,
            status: finding.status,
            summary: finding.summary,
            recommendation: finding.recommendation ?? null,
          })),
      })),
    };

    const response = await client.responses.create({
      model: process.env.OPENAI_MODEL ?? "gpt-4o-mini",
      instructions:
        "You are a concise web security analyst. Write a short, direct summary for a website owner. Explain the overall risk, then list the top remediation priorities. No markdown headings.",
      input: [
        {
          role: "user",
          content: [
            {
              type: "input_text",
              text: JSON.stringify(payload),
            },
          ],
        },
      ],
      max_output_tokens: 260,
    });

    const text = response.output_text.trim();

    return {
      text: text || fallback,
      aiEnhanced: Boolean(text),
    };
  } catch {
    return {
      text: fallback,
      aiEnhanced: false,
    };
  }
}

function buildFallbackSummary(input: SummaryInput) {
  const issues = input.categories
    .flatMap((category) =>
      category.findings
        .filter((finding) => finding.status !== "pass")
        .map((finding) => ({
          title: finding.title,
          recommendation: finding.recommendation,
        })),
    )
    .slice(0, 3);

  if (!issues.length) {
    return `The scan for ${input.hostname} returned a ${input.grade} (${input.score}/100). No major issues were confirmed in the initial probe set. Keep header policy, TLS renewal, and public exposure checks in your regular release process.`;
  }

  const fixes = issues
    .map(
      (issue) =>
        issue.recommendation ??
        `Review the controls around ${issue.title.toLowerCase()}.`,
    )
    .join(" ");

  return `The scan for ${input.hostname} returned a ${input.grade} (${input.score}/100). The main risk areas are ${issues
    .map((issue) => issue.title.toLowerCase())
    .join(", ")}. Prioritize these fixes next: ${fixes}`;
}
