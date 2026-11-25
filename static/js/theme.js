// Saved theme (issue #134), applied before first paint so a dark-mode user
// never sees a light flash. Loaded without defer in <head> by the app, the
// sign-in page and the Pro page; the app's ThemeToggle writes cz-theme.
try { if (localStorage.getItem('cz-theme') === 'dark') document.documentElement.dataset.theme = 'dark'; } catch (e) {}
