import { greaterOrEqual, parse } from '@std/semver';

export const denoSupportsPQC = greaterOrEqual(parse(Deno.version.deno), parse('2.8.2'));
