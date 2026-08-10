const fs = require('fs');
const path = require('path');

const PALETTES = [
  ['#a855f7', '#7c3aed', '#22d3ee'],
  ['#f472b6', '#a855f7', '#6366f1'],
  ['#22d3ee', '#3b82f6', '#a855f7'],
  ['#f59e0b', '#f472b6', '#a855f7'],
  ['#34d399', '#22d3ee', '#6366f1'],
  ['#fb7185', '#a855f7', '#38bdf8']
];

function hashStr(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function pick(str, arr) {
  return arr[hashStr(str) % arr.length];
}

function initials(name) {
  return name
    .split(' ')
    .map((w) => w[0])
    .filter(Boolean)
    .slice(0, 2)
    .join('')
    .toUpperCase();
}

function gradient(str, id) {
  const c = pick(str, PALETTES);
  return `<linearGradient id="${id}" x1="0%" y1="0%" x2="100%" y2="100%">
    <stop offset="0%" stop-color="${c[0]}"/>
    <stop offset="55%" stop-color="${c[1]}"/>
    <stop offset="100%" stop-color="${c[2]}"/>
  </linearGradient>`;
}

function avatarSVG(name, seed) {
  const gid = 'g' + hashStr(seed).toString(36);
  return `<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200" viewBox="0 0 200 200">
  <defs>${gradient(seed, gid)}</defs>
  <rect width="200" height="200" rx="40" fill="url(#${gid})"/>
  <circle cx="100" cy="76" r="34" fill="rgba(0,0,0,0.25)"/>
  <ellipse cx="100" cy="164" rx="58" ry="42" fill="rgba(0,0,0,0.25)"/>
  <text x="100" y="120" font-family="Segoe UI, Arial, sans-serif" font-size="52" font-weight="bold"
    fill="rgba(255,255,255,0.95)" text-anchor="middle" dominant-baseline="middle">${initials(name)}</text>
</svg>`;
}

function postImageSVG(text, seed, w = 640, h = 480) {
  const gid = 'g' + hashStr(seed).toString(36);
  const lines = String(text).split('\n').slice(0, 4);
  const tspans = lines
    .map(
      (l, i) =>
        `<tspan x="32" dy="${i === 0 ? 0 : 1.35}em" fill="rgba(255,255,255,0.92)">${esc(l)}</tspan>`
    )
    .join('');
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}">
  <defs>${gradient(seed, gid)}</defs>
  <rect width="${w}" height="${h}" fill="url(#${gid})"/>
  <circle cx="${w * 0.8}" cy="${h * 0.15}" r="${w * 0.35}" fill="rgba(255,255,255,0.08)"/>
  <circle cx="${w * 0.1}" cy="${h * 0.9}" r="${w * 0.3}" fill="rgba(0,0,0,0.12)"/>
  <text x="32" y="40%" font-family="Segoe UI, Arial, sans-serif" font-size="30" font-weight="bold" fill="rgba(255,255,255,0.95)">${tspans}</text>
</svg>`;
}

function thumbSVG(title, seed, w = 320, h = 180) {
  const gid = 'g' + hashStr(seed).toString(36);
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}">
  <defs>${gradient(seed, gid)}</defs>
  <rect width="${w}" height="${h}" fill="url(#${gid})"/>
  <circle cx="${w * 0.75}" cy="${h * 0.2}" r="${w * 0.3}" fill="rgba(255,255,255,0.1)"/>
  <polygon points="${w / 2},${h / 2 - 18} ${w / 2},${h / 2 + 18} ${w / 2 + 32},${h / 2}"
    fill="rgba(255,255,255,0.9)"/>
  <rect x="10" y="${h - 34}" width="${w - 20}" height="24" rx="12" fill="rgba(0,0,0,0.35)"/>
  <text x="20" y="${h - 18}" font-family="Segoe UI, Arial, sans-serif" font-size="14" font-weight="bold"
    fill="rgba(255,255,255,0.95)">${esc(String(title).slice(0, 40))}</text>
</svg>`;
}

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function writeSVG(dir, filename, svg) {
  const p = path.join(dir, filename);
  fs.writeFileSync(p, svg);
  return p;
}

module.exports = { avatarSVG, postImageSVG, thumbSVG, writeSVG, pick };
