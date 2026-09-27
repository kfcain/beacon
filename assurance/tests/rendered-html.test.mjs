import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
test('portable build has usable entrypoint and local assets',async()=>{
 const html=await readFile(new URL('../portable/dist/index.html',import.meta.url),'utf8');
 assert.match(html,/<div id="root"><\/div>/);assert.match(html,/type="module"/);
 for(const match of html.matchAll(/(?:src|href)="(\/assets\/[^"#]+)"/g))assert.ok((await readFile(new URL('../portable/dist'+match[1],import.meta.url))).length>0);
});
