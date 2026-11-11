import type { Rotator } from '../types.ts';
import { cloudflareApiTokenRotator, type CloudflareApiTokenSpec } from './cloudflareToken.ts';
import { generatedRotator, type GeneratedSpec } from './generated.ts';
import { manualRotator, type ManualSpec } from './manual.ts';
import { staticRotator, type StaticSpec } from './static.ts';
import {
	stripeSecretKeyRotator,
	stripeWebhookSecretRotator,
	type StripeSecretKeySpec,
	type StripeWebhookSecretSpec,
} from './stripe.ts';

export type RotatorSpec =
	| GeneratedSpec
	| StaticSpec
	| ManualSpec
	| StripeSecretKeySpec
	| StripeWebhookSecretSpec
	| CloudflareApiTokenSpec;

export function createRotator(spec: RotatorSpec | Rotator, id: string): Rotator {
	if (!('kind' in spec)) return spec;
	switch (spec.kind) {
		case 'generated':
			return generatedRotator(spec);
		case 'static':
			return staticRotator();
		case 'manual':
			return manualRotator(spec);
		case 'stripe-secret-key':
			return stripeSecretKeyRotator(spec);
		case 'stripe-webhook-secret':
			return stripeWebhookSecretRotator(spec);
		case 'cloudflare-api-token':
			return cloudflareApiTokenRotator(spec);
		default:
			throw new Error(`secret ${id}: unknown rotator kind ${String((spec as { kind: unknown }).kind)}`);
	}
}

export { cloudflareApiTokenRotator, generatedRotator, manualRotator, staticRotator, stripeSecretKeyRotator, stripeWebhookSecretRotator };
export { PRESETS, locateCloudflareToken, runProbe, type CloudflareTokenLocation, type PresetName, type ProbeSpec } from './probes.ts';
export type { CloudflareApiTokenSpec, GeneratedSpec, ManualSpec, StaticSpec, StripeSecretKeySpec, StripeWebhookSecretSpec };
