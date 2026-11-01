# super-secret

Import, push and rotate a project's secrets with 1Password as the store.
One manifest per repository says which env vars exist, where each one is
consumed (a Railway service, a Cloudflare Worker, GitHub Actions, a local
`.env`) and how it is rotated. Dry run is the default; nothing is written
without `--apply`; values never appear in output.

```bash
npx super-secret status                       # what is where, and whether it matches the store
npx super-secret import --from env:.env --apply   # one-time: the current values into the vault
npx super-secret push --apply                 # the store's values to every target, redeploy what changed
npx super-secret plan                         # what a rotation would do
npx super-secret rotate worker-token --apply  # provision → store → push → deploy → probe → revoke
npx super-secret verify --previous --expect-dead  # the backup slot must be dead afterwards
```

Node 22.6 or newer. No runtime dependencies; the CLIs it drives are
[`op`](https://developer.1password.com/docs/cli/), `gh` and `wrangler`, whichever the manifest uses.

## The manifest

`super-secret.config.ts` (or `.mjs`, or `super-secret.json` for projects that are
not TypeScript) in the repository root, or anywhere with `--manifest`:

```ts
import { defineManifest } from 'super-secret';

export default defineManifest({
	store: { kind: 'op', vault: 'my-app', item: 'production', account: 'my.1password.com' },
	targets: {
		cloudflare: { kind: 'cloudflare', cwd: 'worker' },
		github: { kind: 'github', repo: 'me/my-app' },
		railway: {
			kind: 'railway',
			project: '${RAILWAY_PROJECT_ID}',          // read from the store
			environment: '${RAILWAY_ENVIRONMENT_ID}',
			services: ['api', 'worker'],
			token: '${RAILWAY_ACCOUNT_TOKEN}',
		},
		env: { kind: 'env-file', path: '.env' },      // the developer's local copy, kept in step
	},
	secrets: [
		{
			id: 'worker-token',
			description: 'Shared bearer token the API checks on every worker request',
			keys: ['WORKER_TOKEN'],
			targets: { cloudflare: true, railway: true, env: true },
			rotator: { kind: 'generated', length: 48 },
		},
		{
			id: 'railway-account-token',
			keys: ['RAILWAY_ACCOUNT_TOKEN'],
			targets: { github: true, env: true },
			rotator: {
				kind: 'manual',
				create: 'Railway → Account settings → Tokens → Create token',
				retire: 'Railway → Account settings → Tokens → delete the previous token',
				probe: { kind: 'railway-account' },
			},
		},
		{
			id: 'stripe',
			keys: ['STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET'],
			targets: { cloudflare: true },
			rotator: { kind: 'stripe-webhook-secret', url: 'https://api.example.com/stripe/webhook' },
		},
	],
});
```

A secret is a set of env-var names (`keys`) with one rotator and a map of the
targets that receive them. `true` keeps the names; `{ STORE_KEY: 'TARGET_KEY' }`
renames on the way (the same token called `RAILWAY_USAGE_TOKEN` by the app and
`RAILWAY_ACCOUNT_TOKEN` by CI).

Relative paths (`cwd`, `path`, `stateDir`) resolve against the manifest's directory, or against `root` when set (`root: '..'` for a manifest kept in `infra/`).

Config strings may read `${KEY}` from the store or the operator env, so IDs
and tokens live in the vault, not in the manifest.

### Rotator kinds

| kind | provision | revoke |
|---|---|---|
| `generated` | a random value (`length`, `alphabet`: alnum, hex, base64url) | nothing: the old value dies when every consumer has the new one |
| `static` | never: identifiers, usernames, public DSNs | |
| `manual` | the operator mints it where `create` says and pastes it (hidden, or on stdin); checked against `pattern` and `probe` | `retire` is queued as a manual step |
| `stripe-secret-key` | manual roll in the Dashboard, paste; checked against the same account and mode | manual expire |
| `stripe-webhook-secret` | a twin endpoint at `url`; its secret ships | the old endpoint is deleted |
| `cloudflare-api-token` | the token rolls itself in place (needs "API Tokens: Edit") | none |

Probes (`probe` on `generated` and `manual`): `{ kind: 'http', url, headers, bearer, basic, expect }`,
or a preset: `railway-account`, `railway-project`, `github-token`, `stripe-key`,
`anthropic`, `openai`, `openrouter`, `sentry`, `resend`, `synoptic`, `cloudflare-token`.

A TypeScript manifest may pass a `Rotator` or `Target` object instead of a spec for anything
provider-specific (see `src/types.ts`).

### Targets

| kind | writes | reads back | deploy |
|---|---|---|---|
| `railway` | GraphQL `variableCollectionUpsert` per service, `skipDeploys`; optional registry credentials (`registryCredentials: { username, password }` store keys) | values per service | `serviceInstanceRedeploy`, waits for the deployment to settle (`deploy: false` to skip) |
| `cloudflare` | `wrangler secret bulk` in `cwd` | names only | none needed |
| `github` | `gh secret set` (stdin), optional `environment` | names only | |
| `env-file` | a local env file (0600, timestamped backup) | values | |

Readable targets get only the keys that differ from the store. Write-only
targets get every bound key on `push`; `status` shows present/missing for them.

## The store

One Secure Note per deployment target in one vault, with three sections:

| section | field | holds |
|---|---|---|
| `current` | `<KEY>` | the value in use (reference: `op://vault/item/current/KEY`) |
| `previous` | `<KEY>` | the value it replaced, the backup slot |
| `meta` | `<KEY>_rotated_at` | when `current` took over |

Every write moves the live value to `previous` first. `layout: 'flat'` uses
`KEY`, `KEY_previous`, `KEY_rotated_at` without sections instead (an existing
vault laid out that way keeps working). `store: { kind: 'env', file }` is the
bootstrap store for a project that has not moved to 1Password yet.

A second item, `operator` by default, holds what the tooling itself
authenticates with (a Railway account token, `GH_TOKEN`, `CLOUDFLARE_API_TOKEN`,
provider admin keys). The shell env wins; otherwise they are read from that
item, so CI needs exactly one secret, `OP_SERVICE_ACCOUNT_TOKEN`.
`import --operator NAME… --apply` fills it from the shell env.

`op` needs a session: the desktop app's CLI integration locally (set
`store.account` when several accounts are signed in), `OP_SERVICE_ACCOUNT_TOKEN`
in CI. New items are created through a 0600 JSON template so values stay off
argv; `op item edit` only takes assignments on argv, which is acceptable on a
single-user machine or an ephemeral runner.

## What a rotation does

For each selected secret, in manifest order: **provision** the new value;
**queue** the old credential in `.super-secret/pending-revocations.json`
(git-ignore it) so a crash never leaves it live and forgotten; **store** it,
moving the old value to `previous`; **push** it to every bound target without
deploying. Then once: **deploy** each touched target; **probe** every new value;
**revoke** the queued credentials. A failed probe stops before revocation;
`revoke-pending --apply` drains the queue later, `--ack-manual` clears manual
steps you have done by hand.

`--no-deploy`, `--no-revoke`, `--targets a,b` and `--skip-manual` narrow a run.
Manual rotators need a terminal; without one (CI) they are skipped.

## Hosts and pods: `render`

Projects that run on plain hosts or GPU pods keep a committed template of
references and render it where the values are needed:

```
# secrets/prod.env.tpl
API_SECRET=op://my-app/production/current/API_SECRET
DATABASE_URL=op://my-app/production/current/DATABASE_URL
TLS_KEY_B64=op://my-app/production/current/TLS_KEY     # multi-line → base64
PUBLIC_URL=https://example.com                         # literals pass through
```

```bash
npx super-secret render --template secrets/prod.env.tpl --check
npx super-secret render --template secrets/prod.env.tpl --out /run/app/prod.env   # 0600, atomic
```

## From GitHub Actions

```yaml
- uses: 1password/install-cli-action@v4
- run: npx super-secret push --apply --skip-manual
  env:
    OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
```

The service account needs read/write on the vault; everything else comes from
the `operator` item.

## Rules the code keeps

- Secret values never appear in output; `redact()` prints a prefix, a length and a short hash.
- Values reach CLIs over stdin or a 0600 file, never argv (the `op item edit` assignments are the one exception).
- Read-only calls are fine in a dry run; anything that writes checks `ctx.apply` first.
- The manifest is the inventory: a key that is not in it is not managed.

## Releasing

Releases are cut by [semantic-release](https://semantic-release.gitbook.io/) from
`main` in CI (`.github/workflows/ci.yml`), so commits follow
[Conventional Commits](https://www.conventionalcommits.org/): `feat:` bumps the
minor version, `fix:` the patch, a `BREAKING CHANGE:` footer or `feat!:` the
major; `docs:`, `ci:`, `chore:`, `refactor:` and `test:` publish nothing. The
version in `package.json` is a placeholder; the tag, the npm version and the
GitHub release notes come from the commits. The workflow needs one repository
secret, `NPM_TOKEN`, a granular npm token allowed to publish this package.

## Lineage

Extracted from the secrets tooling in two private projects: a TypeScript
pipeline (store interface, rotators, Railway and GitHub targets, revocation
queue) and a Python one (op-backed vault items, `op://` templates rendered on
hosts, dual-password datastore rotation). Datastore rotators (MySQL `RETAIN
CURRENT PASSWORD`, Redis ACL) are the next thing to port.

MIT.
