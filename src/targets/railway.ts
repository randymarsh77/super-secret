import { resolveRef } from '../resolve.ts';
import type { Ctx, Target, Values } from '../types.ts';
import { redact, sleep } from '../util.ts';

export interface RailwayTargetConfig {
	kind: 'railway';
	/** Project UUID, or `${KEY}` from the store / operator env. */
	project: string;
	/** Environment UUID, or `${KEY}`. */
	environment: string;
	/** Service names or UUIDs that receive the variables; `${KEY}` reads a name from the store / operator env. */
	services: string[];
	/**
	 * Where the ACCOUNT token comes from: an operator variable name, or
	 * `${KEY}` to read it from the store or the operator env (a token the app
	 * itself also holds). Default: the first of RAILWAY_API_TOKEN,
	 * RAILWAY_ACCOUNT_TOKEN, RAILWAY_USAGE_TOKEN set in the operator env.
	 */
	token?: string;
	/** Store keys whose values are the services' private-registry pull credentials. */
	registryCredentials?: { username: string; password: string };
	/** Redeploy each service after a push (default true). */
	deploy?: boolean;
	/** How long deploy() waits for each redeploy to settle (default 600). */
	waitSeconds?: number;
}

export const RAILWAY_GQL = 'https://backboard.railway.com/graphql/v2';
const TOKEN_VARS = ['RAILWAY_API_TOKEN', 'RAILWAY_ACCOUNT_TOKEN', 'RAILWAY_USAGE_TOKEN'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type Gql = (query: string, variables: unknown) => Promise<any>;

export function gqlClient(token: string, fetchImpl: typeof fetch = fetch): Gql {
	return async (query, variables) => {
		const r = await fetchImpl(RAILWAY_GQL, {
			method: 'POST',
			headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
			body: JSON.stringify({ query, variables }),
			signal: AbortSignal.timeout(30_000),
		});
		const body = (await r.json()) as { data?: any; errors?: Array<{ message: string }> };
		if (body.errors?.length) throw new Error(`railway: ${body.errors.map((e) => e.message).join('; ')}`);
		return body.data;
	};
}

interface Service {
	id: string;
	name: string;
}

export class RailwayTarget implements Target {
	readonly label: string;
	readonly readable = true;
	readonly name: string;
	private readonly cfg: RailwayTargetConfig;
	private readonly makeClient: (token: string) => Gql;
	private gql?: Gql;
	private services?: Service[];
	private ids?: { project: string; environment: string };

	constructor(cfg: RailwayTargetConfig, name: string, makeClient: (token: string) => Gql = gqlClient) {
		this.cfg = cfg;
		this.name = name;
		this.makeClient = makeClient;
		this.label = `Railway ${name} (${cfg.services.join(', ')})`;
	}

	private async client(ctx: Ctx): Promise<Gql> {
		if (this.gql) return this.gql;
		let token: string | undefined;
		if (this.cfg.token?.startsWith('${')) token = await resolveRef(this.cfg.token, ctx, `${this.label} token`);
		else if (this.cfg.token) token = await ctx.operator.require(this.cfg.token, 'a Railway account token');
		else for (const v of TOKEN_VARS) if ((token = await ctx.operator.get(v))) break;
		if (!token) throw new Error(`railway: no account token in the operator env (one of ${TOKEN_VARS.join(', ')})`);
		this.gql = this.makeClient(token);
		return this.gql;
	}

	private async scope(ctx: Ctx) {
		this.ids ??= {
			project: await resolveRef(this.cfg.project, ctx, `${this.label} project`),
			environment: await resolveRef(this.cfg.environment, ctx, `${this.label} environment`),
		};
		return this.ids;
	}

	/** The configured services resolved to {id, name}; unknown names fail loudly. */
	async resolveServices(ctx: Ctx): Promise<Service[]> {
		if (this.services) return this.services;
		const gql = await this.client(ctx);
		const { project } = await this.scope(ctx);
		const data = await gql(`query($id: String!) { project(id: $id) { services { edges { node { id name } } } } }`, {
			id: project,
		});
		const all: Service[] = (data.project?.services?.edges ?? []).map((e: { node: Service }) => e.node);
		const out: Service[] = [];
		const missing: string[] = [];
		for (const raw of this.cfg.services) {
			const want = await resolveRef(raw, ctx, `${this.label} service`);
			const hit = all.find((s) => s.name === want || (UUID.test(want) && s.id === want));
			if (hit) out.push(hit);
			else missing.push(want);
		}
		if (missing.length)
			throw new Error(
				`railway: service(s) ${missing.join(', ')} not in the project (have: ${all.map((s) => s.name).join(', ')})`
			);
		this.services = out;
		return out;
	}

	async preflight(ctx: Ctx): Promise<string> {
		const gql = await this.client(ctx);
		const me = await gql(`{ me { email } }`, {});
		const services = await this.resolveServices(ctx);
		return `railway: ${me.me?.email ?? 'token ok'}; services ${services.map((s) => s.name).join(', ')}`;
	}

	async read(keys: string[], ctx: Ctx): Promise<Record<string, Values>> {
		const gql = await this.client(ctx);
		const { project, environment } = await this.scope(ctx);
		const out: Record<string, Values> = {};
		for (const svc of await this.resolveServices(ctx)) {
			const data = await gql(
				`query($p: String!, $e: String!, $s: String!) { variables(projectId: $p, environmentId: $e, serviceId: $s) }`,
				{ p: project, e: environment, s: svc.id }
			);
			const vars: Values = data.variables ?? {};
			out[svc.name] = Object.fromEntries(keys.filter((k) => k in vars).map((k) => [k, vars[k]!]));
		}
		return out;
	}

	async set(values: Values, ctx: Ctx): Promise<void> {
		const gql = await this.client(ctx);
		const { project, environment } = await this.scope(ctx);
		const services = await this.resolveServices(ctx);
		const creds = this.cfg.registryCredentials;
		const credKeys = creds ? [creds.username, creds.password] : [];
		const vars = Object.fromEntries(Object.entries(values).filter(([k]) => !credKeys.includes(k)));
		for (const svc of services) {
			for (const [k, v] of Object.entries(vars)) ctx.log.step(`Railway ${svc.name}: set ${k} ← ${redact(v)} (no deploy)`);
			if (ctx.apply && Object.keys(vars).length) {
				await gql(
					`mutation($input: VariableCollectionUpsertInput!) { variableCollectionUpsert(input: $input) }`,
					{ input: { projectId: project, environmentId: environment, serviceId: svc.id, variables: vars, skipDeploys: true } }
				);
			}
		}
		if (creds && credKeys.some((k) => k in values)) {
			const username = values[creds.username] ?? (await ctx.store.get(creds.username));
			const password = values[creds.password] ?? (await ctx.store.get(creds.password));
			if (!username || !password)
				throw new Error(`railway: registry credentials need both ${creds.username} and ${creds.password}`);
			const config = ctx.apply
				? (await gql(`query($id: String!) { environment(id: $id) { config } }`, { id: environment })).environment?.config
				: undefined;
			for (const svc of services) {
				ctx.log.step(`Railway ${svc.name}: registry credentials ← ${username} / ${redact(password)}`);
				if (!ctx.apply) continue;
				// the image rides along: this is the same mutation that sets the
				// source, and a bare registryCredentials update is not documented
				const image: string | undefined = config?.services?.[svc.id]?.source?.image;
				await gql(
					`mutation($env: String!, $svc: String!, $input: ServiceInstanceUpdateInput!) {
					   serviceInstanceUpdate(environmentId: $env, serviceId: $svc, input: $input) }`,
					{ env: environment, svc: svc.id, input: { ...(image ? { source: { image } } : {}), registryCredentials: { username, password } } }
				);
			}
		}
	}

	async deploy(ctx: Ctx): Promise<void> {
		if (this.cfg.deploy === false) {
			ctx.log.note(`${this.label}: deploy disabled in the manifest`);
			return;
		}
		const gql = await this.client(ctx);
		const { project, environment } = await this.scope(ctx);
		for (const svc of await this.resolveServices(ctx)) {
			ctx.log.step(`Railway ${svc.name}: redeploy latest deployment`);
			if (!ctx.apply) continue;
			const before = await latestDeployment(gql, project, environment, svc.id);
			await gql(
				`mutation($env: String!, $svc: String!) { serviceInstanceRedeploy(environmentId: $env, serviceId: $svc) }`,
				{ env: environment, svc: svc.id }
			);
			const deadline = Date.now() + (this.cfg.waitSeconds ?? 600) * 1000;
			let last: Deployment | undefined;
			while (Date.now() < deadline) {
				last = await latestDeployment(gql, project, environment, svc.id);
				if (last && last.id !== before?.id && !PENDING.has(last.status)) break;
				await sleep(10_000);
			}
			if (!last || last.id === before?.id) throw new Error(`railway ${svc.name}: no new deployment appeared in time`);
			if (FAILED.has(last.status)) throw new Error(`railway ${svc.name}: deployment ${last.id} ended ${last.status}`);
			ctx.log.note(`${svc.name}: deployment ${last.id.slice(0, 8)} is ${last.status}`);
		}
	}
}

interface Deployment {
	id: string;
	status: string;
}
const PENDING = new Set(['INITIALIZING', 'QUEUED', 'WAITING', 'BUILDING', 'DEPLOYING', 'NEEDS_APPROVAL']);
const FAILED = new Set(['FAILED', 'CRASHED']);

async function latestDeployment(gql: Gql, project: string, environment: string, serviceId: string) {
	const data = await gql(
		`query($input: DeploymentListInput!) { deployments(first: 1, input: $input) { edges { node { id status } } } }`,
		{ input: { projectId: project, environmentId: environment, serviceId } }
	);
	return (data.deployments?.edges?.[0]?.node as Deployment | undefined) ?? undefined;
}
