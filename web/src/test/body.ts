// What Go renders onto <body>; src/lib/boot.ts reads it at import.
Object.assign(document.body.dataset, {
  admin: "/admin",
  csrf: "test-csrf",
  role: "owner",
  email: "owner@example.com",
  demo: "false",
  version: "v0.0.0-test",
  nonce: "test-nonce",
});
