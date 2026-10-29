import { randomBytes, X509Certificate } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import tls from "node:tls";
import moment from "moment";
import deadHostModel from "../models/dead_host.js";
import proxyHostModel from "../models/proxy_host.js";
import redirectionHostModel from "../models/redirection_host.js";

const positiveInteger = (value, fallback) => {
	const parsed = Number.parseInt(value, 10);
	return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};

const DEFAULT_PROBE_HOST = process.env.CERTIFICATE_PROBE_HOST || "127.0.0.1";
const DEFAULT_PROBE_PORT = positiveInteger(process.env.CERTIFICATE_PROBE_PORT, 443);
const DEFAULT_PROBE_TIMEOUT_MS = positiveInteger(process.env.CERTIFICATE_PROBE_TIMEOUT_MS, 4000);
const DEFAULT_PROBE_ATTEMPTS = 3;
const DEFAULT_PROBE_RETRY_DELAY_MS = 250;
const MAX_PROBED_DOMAINS = 3;
const SYNTHETIC_PROBE_LABEL = "npm-probe";
const MAX_SYNTHETIC_PROBES = 2;
// `expires_on` is stored as a local-time string while a certificate reports GMT.
// A wide tolerance absorbs every timezone offset; a stale row differs by days.
const DATABASE_EXPIRY_TOLERANCE_MS = 24 * 60 * 60 * 1000;

const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

const normalizeFingerprint = (fingerprint) => `${fingerprint || ""}`.replaceAll(":", "").toLowerCase();

const parseServedNotAfter = (value) => {
	const parsed = new Date(value).getTime();
	return Number.isNaN(parsed) ? null : parsed;
};

const parseDatabaseNotAfter = (value) => {
	if (!value) return null;
	if (value instanceof Date) return value.getTime();

	const strict = moment(value, "YYYY-MM-DD HH:mm:ss", true);
	if (strict.isValid()) return strict.valueOf();

	const loose = moment(value);
	return loose.isValid() ? loose.valueOf() : null;
};

/**
 * A certificate for `*.example.com` or `.example.com` cannot be probed directly:
 * TLS needs a concrete SNI name that the host actually answers on.
 */
const isProbeableDomain = (domain) =>
	typeof domain === "string" && domain.length > 0 && !domain.startsWith("*") && !domain.startsWith(".");

/**
 * Builds a throwaway hostname underneath a wildcard binding so the local check
 * can still prove what the wildcard server block serves.
 *
 * SNI cannot carry `*`, so guessing a name is the only way to address a
 * `server_name *.example.com` block. The probe only performs a TLS handshake
 * against nginx on loopback: the name never needs to resolve, and no HTTP
 * request is sent, so no upstream or route has to exist. A fresh random label
 * per check keeps any cache or log from treating two checks as the same name.
 */
const syntheticProbeDomain = (domain) => {
	if (typeof domain !== "string") return null;

	let suffix = "";
	if (domain.startsWith("*.")) suffix = domain.slice(2);
	else if (domain.startsWith(".")) suffix = domain.slice(1);
	if (!suffix) return null;

	return `${SYNTHETIC_PROBE_LABEL}-${randomBytes(4).toString("hex")}.${suffix}`;
};

const certificateInfoOfFile = async (file) => {
	const certificate = new X509Certificate(await fs.readFile(file));
	return { fingerprint: certificate.fingerprint256, notAfter: certificate.validTo };
};

/**
 * Performs a real TLS handshake against the local nginx with the given SNI and
 * returns the SHA-256 fingerprint and expiry of the certificate it presented.
 */
const probeServedCertificate = (domain, options = {}) =>
	new Promise((resolve, reject) => {
		const socket = tls.connect({
			host: options.host ?? DEFAULT_PROBE_HOST,
			port: options.port ?? DEFAULT_PROBE_PORT,
			servername: domain,
			rejectUnauthorized: false,
			timeout: options.timeout ?? DEFAULT_PROBE_TIMEOUT_MS,
		});

		let settled = false;
		const finish = (callback, value) => {
			if (settled) return;
			settled = true;
			socket.destroy();
			callback(value);
		};

		socket.once("secureConnect", () => {
			const peer = socket.getPeerCertificate();
			if (peer?.fingerprint256) {
				finish(resolve, { fingerprint: peer.fingerprint256, notAfter: peer.valid_to });
			} else {
				finish(reject, new Error(`TLS probe for ${domain} returned no certificate`));
			}
		});
		socket.once("error", (err) => finish(reject, err));
		socket.once("timeout", () => finish(reject, new Error(`TLS probe for ${domain} timed out`)));
	});

/**
 * Collects domains that can be used to ask nginx which certificate it serves
 * for this certificate's bindings. Concrete hostnames are preferred; when the
 * certificate is only bound to wildcard hosts, a synthetic name underneath the
 * wildcard is used instead.
 */
const hostDomainsForCertificate = async (certificateId) => {
	const [proxyHosts, redirectionHosts, deadHosts] = await Promise.all([
		proxyHostModel.query().where("certificate_id", certificateId).where("is_deleted", 0),
		redirectionHostModel.query().where("certificate_id", certificateId).where("is_deleted", 0),
		deadHostModel.query().where("certificate_id", certificateId).where("is_deleted", 0),
	]);

	const names = [...proxyHosts, ...redirectionHosts, ...deadHosts]
		.filter((host) => host.enabled !== false && host.enabled !== 0)
		.flatMap((host) => (Array.isArray(host.domain_names) ? host.domain_names : []));

	const concrete = [...new Set(names.filter(isProbeableDomain))].map((domain) => ({
		domain,
		synthetic: false,
	}));

	if (concrete.length) {
		return concrete;
	}

	return names
		.map(syntheticProbeDomain)
		.filter(Boolean)
		.slice(0, MAX_SYNTHETIC_PROBES)
		.map((domain) => ({ domain, synthetic: true }));
};

/**
 * Compares the certificate nginx actually presents with the renewed file and
 * with the expiry stored in the database.
 *
 * `verified`    nginx serves the expected material and the database agrees.
 * `stale`       nginx serves the expected material, but the database expiry
 *               describes a different certificate (the panel is out of date).
 * `mismatch`    nginx answered, but with different certificate material.
 * `unverified`  nginx could not be probed (not listening, timeout, mTLS, ...).
 * `skipped`     nothing is bound to the certificate, so there is no server
 *               block that could be asked.
 */
const verify = async (certificate, options = {}) => {
	const candidates = (options.domains ?? (await certificateServing.hostDomains(certificate.id))).map((entry) =>
		typeof entry === "string" ? { domain: entry, synthetic: false } : entry,
	);
	if (!candidates.length) {
		return { status: "skipped", reason: "no probeable host is bound to this certificate" };
	}

	const liveCertPath = options.liveCertPath || `/etc/letsencrypt/live/npm-${certificate.id}`;
	const fullchain = path.join(liveCertPath, "fullchain.pem");

	let expected;
	if (options.expectedFingerprint) {
		expected = { fingerprint: options.expectedFingerprint, notAfter: null };
	} else {
		try {
			expected = await certificateServing.certificateInfo(fullchain);
		} catch (err) {
			return { status: "unverified", message: `cannot read ${fullchain}: ${err.message}` };
		}
	}

	const databaseNotAfter = certificate.expires_on || null;
	const databaseMs = parseDatabaseNotAfter(databaseNotAfter);
	const attempts = options.attempts ?? DEFAULT_PROBE_ATTEMPTS;
	const retryDelay = options.retryDelay ?? DEFAULT_PROBE_RETRY_DELAY_MS;
	const probeOptions = { host: options.host, port: options.port, timeout: options.timeout };
	const probedDomains = candidates.slice(0, MAX_PROBED_DOMAINS);

	let lastError = null;
	let lastServed = null;

	for (let attempt = 1; attempt <= attempts; attempt++) {
		for (const candidate of probedDomains) {
			try {
				const served = await certificateServing.probe(candidate.domain, probeOptions);
				lastServed = served;
				lastError = null;

				if (normalizeFingerprint(served.fingerprint) !== normalizeFingerprint(expected.fingerprint)) {
					continue;
				}

				const servedMs = parseServedNotAfter(served.notAfter);
				const databaseMatch =
					databaseMs === null || servedMs === null
						? null
						: Math.abs(servedMs - databaseMs) <= DATABASE_EXPIRY_TOLERANCE_MS;

				return {
					status: databaseMatch === false ? "stale" : "verified",
					domain: candidate.domain,
					synthetic: candidate.synthetic,
					expectedFingerprint: expected.fingerprint,
					servedFingerprint: served.fingerprint,
					servedNotAfter: served.notAfter ?? null,
					databaseNotAfter,
					databaseMatch,
				};
			} catch (err) {
				lastError = err;
			}
		}

		if (attempt < attempts) {
			await sleep(retryDelay * attempt);
		}
	}

	if (lastServed) {
		return {
			status: "mismatch",
			domain: probedDomains[0].domain,
			synthetic: probedDomains[0].synthetic,
			expectedFingerprint: expected.fingerprint,
			servedFingerprint: lastServed.fingerprint,
			servedNotAfter: lastServed.notAfter ?? null,
			databaseNotAfter,
			databaseMatch: null,
			message: `nginx serves ${lastServed.fingerprint} for ${probedDomains.map((item) => item.domain).join(", ")}, expected ${expected.fingerprint}`,
		};
	}

	return {
		status: "unverified",
		domain: probedDomains[0].domain,
		synthetic: probedDomains[0].synthetic,
		message: lastError?.message || "nginx did not present a certificate",
	};
};

const certificateServing = {
	certificateInfo: certificateInfoOfFile,
	hostDomains: hostDomainsForCertificate,
	isProbeableDomain,
	normalizeFingerprint,
	probe: probeServedCertificate,
	syntheticProbeDomain,
	verify,
};

export default certificateServing;
