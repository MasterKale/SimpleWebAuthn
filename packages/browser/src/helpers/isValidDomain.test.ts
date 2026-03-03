import { assert, assertFalse } from '@std/assert';
import { isValidDomain } from './isValidDomain.ts';

Deno.test('should handle localhost', () => {
  assert(isValidDomain('localhost'));
});

Deno.test('should handle standard ASCII domains and labels', () => {
  assert(isValidDomain('example.com'));
  assert(isValidDomain('my-site.io'));
  assert(isValidDomain('sub.example.co.uk'));
  assertFalse(isValidDomain('notadomain'));
  assertFalse(isValidDomain(''));
});

Deno.test('should handle punycode domains', () => {
  // Punycode label with ascii domain
  assert(isValidDomain('xn--5lwo46cp2i.co.jp'));
  assert(isValidDomain('xn--5lwo46cp2i.jp'));
  // Punycode label with punycode domain
  assert(isValidDomain('xn--80akjhbed8ahk.xn--p1ai'));
  // ASCII subdomain
  assert(isValidDomain('login.xn--5lwo46cp2i.co.jp'));
  // Punycode subdomain
  assert(isValidDomain('xn--sub.xn--5lwo46cp2i.co.jp'));
});
