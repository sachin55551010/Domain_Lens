import { isIP } from "node:net";
import { domainToASCII } from "node:url";
import { z } from "zod";
import { analyzeDomain } from "../services/domain.service.js";

const domainCheckSchema = z.object({
  domain: z
    .string({ error: "Domain must be a string." })
    .trim()
    .min(1, "Domain is required.")
    // Accept a trailing DNS dot and internationalized domain names, then
    // validate and return the normalized ASCII hostname.
    .transform((value) => domainToASCII(value.replace(/\.$/, "").toLowerCase()))
    .refine(
      (domain) => domain.length <= 253,
      "Domain must be 253 characters or fewer.",
    )
    .refine(
      (domain) => isIP(domain) === 0,
      "Enter a domain name, not an IP address.",
    )
    .refine((domain) => {
      if (!domain) return false;

      const labels = domain.split(".");
      const validLabels = labels.every(
        (label) =>
          label.length <= 63 &&
          /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label),
      );

      return labels.length >= 2 && validLabels && /[a-z]/i.test(labels.at(-1));
    }, "Enter a valid domain name, such as example.com."),
});

export const domainCheck = async (req, res) => {
  const result = domainCheckSchema.safeParse(req.body);

  if (!result.success) {
    return res.status(400).json({
      success: false,
      errors: result.error.issues.map((issue) => ({
        field: issue.path.join("."),
        message: issue.message,
      })),
    });
  }

  const domain = result.data.domain;

  try {
    const analysis = await analyzeDomain(domain);

    return res.status(200).json({
      success: true,
      domain,
      dns: analysis.root.dns,
      ports: analysis.root.ports,
      subdomains: analysis.subdomains,
      discovery: analysis.discovery,
    });
  } catch (error) {
    const message =
      error.code === "ENOENT"
        ? "Subfinder was not found. Make sure it is on PATH or set SUBFINDER_PATH."
        : error.code === "SUBFINDER_FAILED"
          ? `Subfinder failed: ${error.message}`
          : "Domain analysis could not be completed. Please try again.";

    return res.status(503).json({
      success: false,
      domain,
      message,
    });
  }
};
