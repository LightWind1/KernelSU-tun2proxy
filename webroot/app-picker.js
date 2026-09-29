// Pure list helpers shared by the WebUI and Node regression tests.
function filterAppEntries(entries, query, selectedOnly, selected) {
  const q = String(query || '').trim().toLocaleLowerCase();
  return entries.filter(app =>
    (!selectedOnly || selected.has(app.package)) &&
    (!q || app.package.toLocaleLowerCase().includes(q) ||
      String(app.label || '').toLocaleLowerCase().includes(q))
  );
}
function setMatchingSelection(selected, entries, checked) {
  for (const app of entries) {
    if (checked) selected.add(app.package);
    else selected.delete(app.package);
  }
}
if (typeof module !== 'undefined') module.exports = {filterAppEntries, setMatchingSelection};
