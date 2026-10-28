(function () {
  var adminPath = document.body.dataset.adminPath || '';

  // Ledger chart style: colors come from the theme's --fn-* variables, so
  // the charts follow light/dark mode (read once, at page load).
  var css = getComputedStyle(document.documentElement);
  function v(name) { return css.getPropertyValue(name).trim(); }
  var ink = v('--fn-ink'), muted = v('--fn-muted'), rule = v('--fn-rule'),
      danger = v('--fn-danger'), card = v('--fn-card'), edge = v('--fn-edge');

  Chart.defaults.font.family = "'JetBrains Mono', ui-monospace, monospace";
  Chart.defaults.font.size = 10;
  Chart.defaults.color = muted;

  var tooltip = {
    backgroundColor: card,
    titleColor: ink,
    bodyColor: ink,
    borderColor: edge,
    borderWidth: 1,
    cornerRadius: 0,
    padding: 8,
    displayColors: false,
  };

  fetch(adminPath + '/api/traffic')
    .then(function (res) { return res.json(); })
    .then(function (traffic) {
      var el = document.getElementById('trafficChart');
      if (!el) return;
      new Chart(el, {
        type: 'bar',
        data: {
          labels: traffic.labels,
          datasets: [
            { label: 'Allowed', data: traffic.allowed, backgroundColor: ink, stack: 'req' },
            { label: 'Blocked', data: traffic.blocked, backgroundColor: danger, stack: 'req' },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: { intersect: false, mode: 'index' },
          datasets: { bar: { barPercentage: 0.7, categoryPercentage: 0.9 } },
          plugins: {
            legend: { display: false },
            tooltip: Object.assign({}, tooltip, {
              callbacks: {
                label: function (ctx) { return ctx.dataset.label + ': ' + ctx.raw; },
              },
            }),
          },
          scales: {
            x: {
              stacked: true,
              grid: { display: false },
              border: { color: edge },
              ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 8 },
            },
            y: {
              stacked: true,
              beginAtZero: true,
              border: { display: false },
              grid: { color: rule, drawTicks: false },
              ticks: { padding: 6, maxTicksLimit: 4, precision: 0 },
            },
          },
        },
      });
    });

  fetch(adminPath + '/api/threats')
    .then(function (res) { return res.json(); })
    .then(function (threats) {
      var el = document.getElementById('threatsChart');
      if (!el) return;
      new Chart(el, {
        type: 'bar',
        data: {
          labels: threats.labels,
          datasets: [{ data: threats.counts, backgroundColor: danger, maxBarThickness: 14 }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
            tooltip: Object.assign({}, tooltip, {
              callbacks: { label: function (ctx) { return ctx.raw + ' blocked'; } },
            }),
          },
          scales: {
            x: { grid: { display: false }, border: { color: edge } },
            y: { display: false, beginAtZero: true },
          },
        },
      });
    });
})();
