import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';

const require = createRequire(import.meta.url);
const braces = require('braces');

test('ordinary brace patterns still expand', () => {
  assert.deepEqual(braces('{a,b}', {expand: true}), ['a', 'b']);
  assert.deepEqual(braces('file.{js,ts}', {expand: true}), ['file.js', 'file.ts']);
});

test('deep brace nesting throws before the stack is exhausted', () => {
  const pattern = `${'{'.repeat(101)}${'}'.repeat(101)}`;
  assert.throws(() => braces(pattern), RangeError);
  assert.throws(() => braces.expand(pattern), RangeError);
});
