const { backupNow, listBackups } = require('./backup');

const action = process.argv[2] || 'now';

if (action === 'list') {
  const list = listBackups();
  if (!list.length) console.log('Бэкапов пока нет.');
  for (const b of list) {
    console.log(`  ${b.file}  (${(b.size / 1024).toFixed(1)} KB, ${b.mtime.toISOString()})`);
  }
} else {
  const f = backupNow();
  console.log('Бэкап создан:', f);
}
