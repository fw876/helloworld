#!/usr/bin/env node
// Use the real LuCI CBI dependency evaluator, including checkbox empty values.
const fs = require('fs');
const vm = require('vm');
const assert = require('assert');
const path = require('path');
const cbi = fs.readFileSync(process.argv[2], 'utf8');
const client = fs.readFileSync(path.join(__dirname, '../luasrc/model/cbi/shadowsocksr/client.lua'), 'utf8');
const filter = client.slice(client.indexOf('o = s:option(Flag, "filter_aaaa"'), client.indexOf('if is_finded("chinadns-ng") then', client.indexOf('o = s:option(Flag, "filter_aaaa"')));
const deps = [...filter.matchAll(/o:depends\(\{pdnsd_enable = "(\d+)", ipv6_support = (false|"0")\}\)/g)]
    .map(m => ({ pdnsd_enable: m[1], ipv6_support: m[2] === 'false' ? false : '0' }));
assert.strictEqual(deps.length, 3);
const fields = { pdnsd_enable: { type: 'select', value: '1' }, ipv6_support: { type: 'checkbox', value: '1', checked: false } };
const ctx = { document: { querySelectorAll: query => [fields[query.match(/id="([^"]+)"/)[1]]] } };
vm.createContext(ctx);
vm.runInContext(cbi.slice(cbi.indexOf('function cbi_d_checkvalue('), cbi.indexOf('function cbi_d_update(')), ctx);
for (const mode of ['0', '1', '4', '6', '7']) {
    fields.pdnsd_enable.value = mode;
    for (const checked of [false, true, false]) {
        fields.ipv6_support.checked = checked;
        assert.strictEqual(ctx.cbi_d_check(deps), !checked && ['1', '4', '7'].includes(mode));
    }
}
assert.match(filter, /function o\.remove\(self, section\)\s*end/);
console.log('PASS: actual CBI checkbox dependencies toggle immediately and preserve the saved filter');
