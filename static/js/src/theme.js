// Saved theme (issue #134), applied before first paint so a dark-mode user
// never sees a light flash. Loaded without defer in <head>; the toggle lives
// in motion.js.
try { if (localStorage.getItem('cz-theme') === 'dark') document.documentElement.dataset.theme = 'dark'; } catch (e) {}
