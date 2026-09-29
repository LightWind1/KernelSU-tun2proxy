const assert = require('node:assert/strict');
const {filterAppEntries, setMatchingSelection} = require('../webroot/app-picker.js');
const apps = [
  {package:'com.android.browser', label:'浏览器', uid:10118},
  {package:'com.example.chat', label:'聊天工具', uid:10200},
  {package:'org.example.browser', label:'Browser Beta', uid:10201}
];
const selected = new Set(['com.example.chat']);
assert.deepEqual(filterAppEntries(apps, '浏览', false, selected).map(a=>a.package), ['com.android.browser']);
assert.deepEqual(filterAppEntries(apps, 'BROWSER', false, selected).map(a=>a.package), ['com.android.browser','org.example.browser']);
assert.deepEqual(filterAppEntries(apps, '聊天', true, selected).map(a=>a.package), ['com.example.chat']);
assert.equal(filterAppEntries(apps, '浏览', true, selected).length, 0);
setMatchingSelection(selected, filterAppEntries(apps, 'browser', false, selected), true);
assert.deepEqual([...selected].sort(), ['com.android.browser','com.example.chat','org.example.browser']);
setMatchingSelection(selected, filterAppEntries(apps, 'browser', false, selected), false);
assert.deepEqual([...selected], ['com.example.chat']);
console.log('app picker tests passed');
