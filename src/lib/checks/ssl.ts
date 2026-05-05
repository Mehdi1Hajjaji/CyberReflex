import tls from "node:tls";
import type { CheckFinding, NormalizedTarget } from "./types";
import { createCheckResult, errorCheck } from "./utils";

type TlsProbeResult = {
  authorized: boolean;
  authorizationError: string | null;
  protocol: string | null;
  validFrom: string | null;
  validTo: string | null;
  issuer: string | null;
  subject: string | null;
};

export async function checkSsl(target: NormalizedTarget) {
  try {
    const result = await probeTls(target.hostname);
    const findings: CheckFinding[] = [];

    findings.push(
      target.protocol === "https:"
        ? {
            id: "https-url",
            title: "HTTPS target",
            status: "pass",
            severity: "info",
            summary: "The normalized target uses HTTPS.",
          }
        : {
            id: "https-url",
            title: "HTTP target",
            status: "fail",
            severity: "high",
            summary: "The normalized target still uses HTTP.",
            recommendation: "Redirect the canonical site to HTTPS.",
          },
    );

    findings.push(
      result.authorized
        ? {
            id: "certificate-trust",
            title: "Certificate is trusted",
            status: "pass",
            severity: "info",
            summary: "The certificate chain is accepted by the Node.js trust store.",
          }
        : {
            id: "certificate-trust",
            title: "Certificate trust issue",
            status: "fail",
            severity: "high",
            summary: result.authorizationError ?? "The certificate chain is not trusted.",
            recommendation: "Install a valid certificate and complete intermediate chain.",
          },
    );

    findings.push(buildExpiryFinding(result.validTo));

    findings.push(
      result.protocol === "TLSv1.2" || result.protocol === "TLSv1.3"
        ? {
            id: "tls-protocol",
            title: "Modern TLS negotiated",
            status: "pass",
            severity: "info",
            summary: `The server negotiated ${result.protocol}.`,
          }
        : {
            id: "tls-protocol",
            title: "TLS protocol could be stronger",
            status: "warning",
            severity: "medium",
            summary: result.protocol
              ? `The server negotiated ${result.protocol}.`
              : "The negotiated TLS protocol could not be determined.",
            recommendation: "Serve TLS 1.2 or TLS 1.3 and disable older versions.",
          },
    );

    return createCheckResult({
      id: "ssl",
      name: "SSL/TLS Certificate",
      findings,
      summary: findings.some((finding) => finding.status === "fail")
        ? "TLS is reachable, but the certificate or HTTPS posture needs attention."
        : "TLS certificate and protocol posture look healthy from this lightweight probe.",
      raw: result,
    });
  } catch (error) {
    return errorCheck("ssl", "SSL/TLS Certificate", error, {
      hostname: target.hostname,
      port: 443,
    });
  }
}

function probeTls(hostname: string) {
  return new Promise<TlsProbeResult>((resolve, reject) => {
    const socket = tls.connect({
      host: hostname,
      port: 443,
      servername: hostname,
      rejectUnauthorized: false,
    });
    let settled = false;

    const finish = (callback: () => void) => {
      if (settled) return;
      settled = true;
      callback();
      socket.end();
      socket.destroy();
    };

    socket.setTimeout(4_000, () => finish(() => reject(new Error("TLS probe timed out."))));
    socket.once("error", (error) => finish(() => reject(error)));
    socket.once("secureConnect", () => {
      const certificate = socket.getPeerCertificate();
      finish(() =>
        resolve({
          authorized: socket.authorized,
          authorizationError:
            typeof socket.authorizationError === "string" ? socket.authorizationError : null,
          protocol: socket.getProtocol() ?? null,
          validFrom: certificate.valid_from ?? null,
          validTo: certificate.valid_to ?? null,
          issuer: stringifyCertificateName(certificate.issuer?.CN),
          subject: stringifyCertificateName(certificate.subject?.CN),
        }),
      );
    });
  });
}

function buildExpiryFinding(validTo: string | null): CheckFinding {
  if (!validTo) {
    return {
      id: "certificate-expiry",
      title: "Certificate expiry unavailable",
      status: "warning",
      severity: "low",
      summary: "The certificate expiry date could not be parsed.",
    };
  }

  const daysRemaining = Math.round((new Date(validTo).getTime() - Date.now()) / 86_400_000);

  if (Number.isNaN(daysRemaining) || daysRemaining < 0) {
    return {
      id: "certificate-expiry",
      title: "Certificate appears expired",
      status: "fail",
      severity: "high",
      summary: "The certificate expiry date is invalid or already past.",
      evidence: { validTo },
    };
  }

  if (daysRemaining < 14) {
    return {
      id: "certificate-expiry",
      title: "Certificate expires soon",
      status: "fail",
      severity: "medium",
      summary: `The certificate expires in ${daysRemaining} days.`,
      recommendation: "Renew the certificate and verify automated renewal.",
    };
  }

  if (daysRemaining < 45) {
    return {
      id: "certificate-expiry",
      title: "Certificate renewal window is close",
      status: "warning",
      severity: "low",
      summary: `The certificate expires in ${daysRemaining} days.`,
    };
  }

  return {
    id: "certificate-expiry",
    title: "Certificate validity is healthy",
    status: "pass",
    severity: "info",
    summary: `The certificate has ${daysRemaining} days remaining.`,
  };
}

function stringifyCertificateName(value: string | string[] | undefined) {
  if (Array.isArray(value)) return value.join(", ");
  return value ?? null;
}

