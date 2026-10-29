import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

const testRoot = await mkdtemp(path.join(os.tmpdir(), "npm-certificate-serving-test-"));
process.env.NPM_KEYS_FILE = path.join(testRoot, "keys.json");
process.env.DB_SQLITE_FILE = path.join(testRoot, "database.sqlite");

const { default: serving } = await import("../internal/certificate-serving.js");

const served = (fingerprint, notAfter = "Dec 27 12:45:19 2026 GMT") => ({ fingerprint, notAfter });

const withStubs = async (stubs, run) => {
	const originals = {};
	for (const [key, value] of Object.entries(stubs)) {
		originals[key] = serving[key];
		serving[key] = value;
	}
	try {
		await run();
	} finally {
		Object.assign(serving, originals);
	}
};

test("serving verification accepts the certificate nginx actually presents", async () => {
	const probed = [];

	await withStubs(
		{
			hostDomains: async () => ["portal.example.test"],
			certificateInfo: async () => served("AA:BB:CC"),
			probe: async (domain) => {
				probed.push(domain);
				return served("aa:bb:cc");
			},
		},
		async () => {
			const result = await serving.verify(
				{ id: 5, expires_on: "2026-12-27 12:45:19" },
				{ liveCertPath: "/tmp/irrelevant" },
			);

			assert.equal(result.status, "verified");
			assert.equal(result.domain, "portal.example.test");
			assert.equal(result.expectedFingerprint, "AA:BB:CC");
			assert.equal(result.servedFingerprint, "aa:bb:cc");
			assert.equal(result.databaseMatch, true);
			assert.equal(result.servedNotAfter, "Dec 27 12:45:19 2026 GMT");
			assert.deepEqual(probed, ["portal.example.test"]);
		},
	);
});

test("serving verification reports a stale panel when nginx serves a newer certificate than the database", async () => {
	await withStubs(
		{
			hostDomains: async () => ["portal.example.test"],
			certificateInfo: async () => served("AA:BB:CC"),
			probe: async () => served("AA:BB:CC", "Mar 01 00:00:00 2027 GMT"),
		},
		async () => {
			const result = await serving.verify(
				{ id: 5, expires_on: "2026-12-27 12:45:19" },
				{ liveCertPath: "/tmp/irrelevant", attempts: 1 },
			);

			assert.equal(result.status, "stale");
			assert.equal(result.databaseMatch, false);
			assert.equal(result.servedNotAfter, "Mar 01 00:00:00 2027 GMT");
			assert.equal(result.databaseNotAfter, "2026-12-27 12:45:19");
		},
	);
});

test("serving verification reports a mismatch when nginx still uses another certificate", async () => {
	await withStubs(
		{
			hostDomains: async () => ["portal.example.test"],
			certificateInfo: async () => served("AA:BB:CC"),
			probe: async () => served("DD:EE:FF"),
		},
		async () => {
			const result = await serving.verify(
				{ id: 5, expires_on: "2026-12-27 12:45:19" },
				{ liveCertPath: "/tmp/irrelevant", attempts: 1 },
			);

			assert.equal(result.status, "mismatch");
			assert.match(result.message, /expected AA:BB:CC/);
		},
	);
});

test("serving verification is skipped when no host is bound to the certificate", async () => {
	await withStubs(
		{
			hostDomains: async () => [],
			certificateInfo: async () => served("AA:BB:CC"),
			probe: async () => served("AA:BB:CC"),
		},
		async () => {
			const result = await serving.verify({ id: 5 }, { liveCertPath: "/tmp/irrelevant" });

			assert.equal(result.status, "skipped");
			assert.match(result.reason, /no probeable host/);
		},
	);
});

test("serving verification reports an unreachable edge without claiming a mismatch", async () => {
	await withStubs(
		{
			hostDomains: async () => ["portal.example.test"],
			certificateInfo: async () => served("AA:BB:CC"),
			probe: async () => {
				throw new Error("connect ECONNREFUSED 127.0.0.1:443");
			},
		},
		async () => {
			const result = await serving.verify({ id: 5 }, { liveCertPath: "/tmp/irrelevant", attempts: 1 });

			assert.equal(result.status, "unverified");
			assert.match(result.message, /ECONNREFUSED/);
		},
	);
});

test("serving verification reports an unreadable certificate file", async () => {
	await withStubs(
		{
			hostDomains: async () => ["portal.example.test"],
			certificateInfo: async () => {
				throw new Error("ENOENT");
			},
		},
		async () => {
			const result = await serving.verify({ id: 5 }, { liveCertPath: "/tmp/irrelevant" });

			assert.equal(result.status, "unverified");
			assert.match(result.message, /cannot read/);
		},
	);
});

test("a wildcard-only binding is verified through a synthetic subdomain", async () => {
	const probed = [];

	await withStubs(
		{
			hostDomains: async () => [{ domain: "npm-probe-1a2b3c4d.example.test", synthetic: true }],
			certificateInfo: async () => served("AA:BB:CC"),
			probe: async (domain) => {
				probed.push(domain);
				return served("AA:BB:CC");
			},
		},
		async () => {
			const result = await serving.verify({ id: 5 }, { liveCertPath: "/tmp/irrelevant" });

			assert.equal(result.status, "verified");
			assert.equal(result.synthetic, true);
			assert.deepEqual(probed, ["npm-probe-1a2b3c4d.example.test"]);
		},
	);
});

test("synthetic probe names stay underneath the wildcard and differ per check", () => {
	const first = serving.syntheticProbeDomain("*.example.test");
	const second = serving.syntheticProbeDomain("*.example.test");

	assert.match(first, /^npm-probe-[0-9a-f]{8}\.example\.test$/);
	assert.notEqual(first, second);
	assert.match(serving.syntheticProbeDomain(".ops.example.test"), /^npm-probe-[0-9a-f]{8}\.ops\.example\.test$/);
	assert.equal(serving.syntheticProbeDomain("example.test"), null);
});

test("wildcard and dot-prefixed names cannot be probed directly", () => {
	assert.equal(serving.isProbeableDomain("portal.example.test"), true);
	assert.equal(serving.isProbeableDomain("*.example.test"), false);
	assert.equal(serving.isProbeableDomain(".example.test"), false);
	assert.equal(serving.isProbeableDomain(""), false);
	assert.equal(serving.isProbeableDomain(undefined), false);
});
