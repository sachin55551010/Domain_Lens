import { spawn } from "node:child_process";
import { lookup } from "node:dns/promises";
import { createConnection } from "node:net";
import pLimit from "p-limit";

const getSubfinderPath = () => process.env.SUBFINDER_PATH || "subfinder";
const DNS_NO_ADDRESS_CODES = new Set(["ENOTFOUND", "ENODATA", "EAI_NODATA"]);
const PORTS_TO_CHECK = [80, 443];
const PORT_TIMEOUT_MS = 2000;
const SUBFINDER_TIMEOUT_MS = 45_000;
const MAX_SUBDOMAINS = 30;
const MAX_ADDRESSES_PER_HOST = 2;
const dnsLookupLimit = pLimit(8);
const portCheckLimit = pLimit(8);

/** Run Subfinder and collect its plain-text, one-host-per-line output. */
export const discoverSubdomains = (domain) =>
  new Promise((resolve, reject) => {
    const child = spawn(
      getSubfinderPath(),
      ["-d", domain, "-silent", "-timeout", "10", "-max-time", "1"],
      {
        shell: false,
        stdio: ["ignore", "pipe", "ignore"],
      },
    );

    const subdomains = new Set();
    let outputBuffer = "";
    let timedOut = false;
    let truncated = false;
    let settled = false;

    const addLine = (line) => {
      let hostname = line.trim().toLowerCase().replace(/\.$/, "");
      if (!hostname) return;

      // Also accept JSONL output if the Subfinder command is changed later.
      if (hostname.startsWith("{")) {
        try {
          hostname = JSON.parse(hostname).host?.toLowerCase() ?? "";
        } catch {
          return;
        }
      }

      if (hostname === domain || !hostname.endsWith(`.${domain}`)) return;
      if (subdomains.has(hostname)) return;

      if (subdomains.size >= MAX_SUBDOMAINS) {
        truncated = true;
        child.kill("SIGTERM");
        return;
      }

      subdomains.add(hostname);
    };

    const timeout = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
    }, SUBFINDER_TIMEOUT_MS);

    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      outputBuffer += chunk;
      const lines = outputBuffer.split(/\r?\n/);
      outputBuffer = lines.pop() ?? "";
      lines.forEach(addLine);
    });

    child.once("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      reject(error);
    });

    child.once("close", (code) => {
      if (outputBuffer.trim()) addLine(outputBuffer);
      if (settled) return;
      settled = true;
      clearTimeout(timeout);

      if (code !== 0 && !timedOut && !truncated) {
        const error = new Error(`Subfinder exited with code ${code}.`);
        error.code = "SUBFINDER_FAILED";
        reject(error);
        return;
      }

      resolve({
        subdomains: [...subdomains],
        timedOut,
        truncated,
      });
    });
  });

/** Resolve a hostname to IPv4 and/or IPv6 addresses. */
export const resolveDomain = async (hostname) => {
  try {
    const addresses = await lookup(hostname, { all: true });

    return {
      resolved: addresses.length > 0,
      addresses: addresses.map(({ address, family }) => ({ address, family })),
    };
  } catch (error) {
    if (DNS_NO_ADDRESS_CODES.has(error?.code)) {
      return { resolved: false, addresses: [] };
    }

    throw error;
  }
};

/** Test whether a TCP connection can be opened to one address and port. */
const checkTcpPort = (address, port) =>
  new Promise((resolve) => {
    let finished = false;
    let socket;

    const finish = (status) => {
      if (finished) return;
      finished = true;
      socket?.destroy();
      resolve({ address, port, status });
    };

    socket = createConnection(
      { host: address, port, timeout: PORT_TIMEOUT_MS },
      () => finish("open"),
    );

    socket.once("timeout", () => finish("timeout"));
    socket.once("error", (error) =>
      finish(error.code === "ECONNREFUSED" ? "closed" : "unreachable"),
    );
  });

const checkHostPorts = async (addresses) => {
  const addressesToCheck = addresses.slice(0, MAX_ADDRESSES_PER_HOST);

  return Promise.all(
    PORTS_TO_CHECK.map(async (port) => {
      const checks = await Promise.all(
        addressesToCheck.map((address) =>
          portCheckLimit(() => checkTcpPort(address.address, port)),
        ),
      );

      return {
        port,
        available: checks.some((check) => check.status === "open"),
        checks,
      };
    }),
  );
};

const enrichSubdomain = async (hostname) => {
  let dns;

  try {
    dns = await dnsLookupLimit(() => resolveDomain(hostname));
  } catch {
    dns = { resolved: false, addresses: [], lookupFailed: true };
  }

  return {
    hostname,
    dns,
    ports: dns.resolved ? await checkHostPorts(dns.addresses) : [],
  };
};

/** Discover subdomains with Subfinder, then resolve and check their web ports. */
export const analyzeDomain = async (domain) => {
  const [rootDns, discovery] = await Promise.all([
    resolveDomain(domain),
    discoverSubdomains(domain),
  ]);

  const [rootPorts, subdomains] = await Promise.all([
    rootDns.resolved ? checkHostPorts(rootDns.addresses) : [],
    Promise.all(discovery.subdomains.map(enrichSubdomain)),
  ]);

  return {
    root: { dns: rootDns, ports: rootPorts },
    subdomains,
    discovery: {
      method: "Subfinder passive sources",
      complete: false,
      found: discovery.subdomains.length,
      truncated: discovery.truncated,
      timedOut: discovery.timedOut,
      maxResults: MAX_SUBDOMAINS,
    },
  };
};
