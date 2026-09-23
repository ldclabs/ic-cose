import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Actor, HttpAgent } from '@icp-sdk/core/agent';
import { createActor as createCose } from '../declarations/ic_cose_canister/index.js';
import { createActor as createWasm } from '../declarations/ic_wasm_canister/index.js';

test('actor factories preserve supplied agents and never fetch a root key', async () => {
  const previous = process.env.DFX_NETWORK;
  try {
    for (const network of [undefined, 'local', 'ic']) {
      if (network === undefined) delete process.env.DFX_NETWORK;
      else process.env.DFX_NETWORK = network;
      for (const create of [createCose, createWasm]) {
        const agent = new HttpAgent({ host: 'https://icp-api.io' });
        const root = agent.rootKey;
        agent.fetchRootKey = async () => assert.fail('supplied agent must not fetch a root key');
        const actor = create('aaaaa-aa', { agent });
        assert.equal(Actor.agentOf(actor), agent);
        assert.equal(agent.rootKey, root);
      }
    }
    await new Promise(resolve => setImmediate(resolve));
  } finally {
    if (previous === undefined) delete process.env.DFX_NETWORK;
    else process.env.DFX_NETWORK = previous;
  }
});

test('example bindings match the canonical generated interfaces', async () => {
  for (const name of ['ic_cose_canister', 'ic_wasm_canister']) {
    for (const file of [`${name}.did`, `${name}.did.js`, `${name}.did.d.ts`, 'index.js', 'index.d.ts']) {
      const canonical = await readFile(new URL(`../../../src/declarations/${name}/${file}`, import.meta.url), 'utf8');
      const example = await readFile(new URL(`../declarations/${name}/${file}`, import.meta.url), 'utf8');
      assert.equal(example, canonical);
    }
  }
  const actor = createCose('aaaaa-aa', { agent: new HttpAgent({ host: 'https://icp-api.io' }) });
  for (const method of ['namespace_get_info_v2', 'namespace_list_members', 'namespace_list_setting_keys_v2', 'admin_migrate_legacy_namespace_acls_page']) {
    assert.equal(typeof actor[method], 'function');
  }
});
