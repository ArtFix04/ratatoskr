/* Ygg-Tunnel UI — shared utilities loaded on every page */

// Expose fmtBytes globally so dashboard.html inline script can use it
function fmtBytes(n) {
  if (n < 1024)        return `${n} B`;
  if (n < 1024 ** 2)   return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3)   return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}
