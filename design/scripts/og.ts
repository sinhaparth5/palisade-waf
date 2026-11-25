// Social preview images (1200x630) for home and each group, rendered by headless Chrome.
//
//   bun run og        # writes public/og/<slug>.png
//
// Re-run after changing a group's title, blurb or art, or the logo.
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

import { groups } from '../app/data/work.ts'

const root = resolve(import.meta.dirname, '..')
const mark = readFileSync(join(root, 'public/favicon.svg'), 'utf8')
// Same order as the section tones in site.css (look-1 … look-6).
const tones = ['#eef0f4', '#f8f1ec', '#0f1022', '#f5efe5', '#ece9ff', '#e3eafd']

const pages = [
  {
    slug: 'home',
    title: 'Built from the metal up.',
    blurb: 'Firewalls, storage engines, lock-free queues, a RISC-V chip and public-data sites.',
    art: 'observatory',
    bg: tones[0],
  },
  ...groups.map((g, i) => ({ slug: g.slug, title: g.title, blurb: g.blurb, art: g.art, bg: tones[i % 6] })),
]

const tmp = mkdtempSync(join(tmpdir(), 'og-'))
for (let p of pages) {
  let ink = p.bg === '#0f1022' ? '#f3f3fb' : '#14151f'
  let html = `<!doctype html>
<style>
@font-face{font-family:Archivo;src:url(file://${root}/public/fonts/archivo.woff2);font-weight:100 900;font-stretch:62% 125%}
@font-face{font-family:"JetBrains Mono";src:url(file://${root}/public/fonts/jetbrains-mono.woff2);font-weight:100 800}
*{margin:0;box-sizing:border-box}
body{width:1200px;height:630px;overflow:hidden;color:${ink};font-family:Archivo;padding:64px 72px;display:grid;grid-template-columns:1fr 440px;gap:32px;
  background:radial-gradient(ellipse 45% 60% at 80% 45%,rgb(123 108 240/.35),transparent 70%),radial-gradient(ellipse 35% 30% at 80% 92%,rgb(255 106 61/.3),transparent 70%),${p.bg}}
.l{display:flex;flex-direction:column;justify-content:space-between}
.brand{display:flex;align-items:center;gap:12px;font-weight:800;font-variation-settings:"wdth" 62;font-size:34px;text-transform:uppercase}
.brand svg{width:40px;height:40px}.brand em{font:500 13px "JetBrains Mono";letter-spacing:.14em;opacity:.7}
h1{font-weight:800;font-variation-settings:"wdth" 62;text-transform:uppercase;font-size:${p.title.length < 24 ? 96 : 84}px;line-height:.88}
p{font-size:26px;line-height:1.35;opacity:.82;margin-top:20px;max-width:560px}
.u{font:500 15px "JetBrains Mono";letter-spacing:.1em;text-transform:uppercase;opacity:.7}
.r{display:grid;place-items:center}.r img{max-width:440px;max-height:540px}
</style>
<div class="l"><div class="brand">${mark}Astrarecons<em>Labs</em></div><div><h1>${p.title}</h1><p>${p.blurb}</p></div><div class="u">+ astrareconslabs.com</div></div>
<div class="r"><img src="file://${root}/public/art/${p.art}.webp"></div>`
  let file = join(tmp, `${p.slug}.html`)
  writeFileSync(file, html)
  let png = join(root, 'public/og', `${p.slug}.png`)
  execFileSync('google-chrome', [
    '--headless=new',
    '--disable-gpu',
    '--hide-scrollbars',
    '--allow-file-access-from-files',
    '--virtual-time-budget=5000',
    '--window-size=1200,630',
    `--screenshot=${png}`,
    `file://${file}`,
  ], { stdio: 'ignore' })
  console.log(png)
}
rmSync(tmp, { recursive: true })
