/**
 * Восстановление БД из зашифрованного бэкапа.
 * ВАЖНО: выполнять только при остановленном сервере!
 *   npm run restore -- space-2026-01-01T00-00-00-000Z.db.enc
 */
const { restoreBackup, listBackups } = require('./backup');

const target = process.argv[2];

if (!target) {
  console.log('Список доступных бэкапов:');
  for (const b of listBackups()) {
    console.log(`  ${b.file}  (${(b.size / 1024).toFixed(1)} KB, ${b.mtime.toISOString()})`);
  }
  console.log('\nИспользование: npm run restore -- <имя_файла>');
  process.exit(1);
}

try {
  restoreBackup(target);
  console.log('БД восстановлена из бэкапа:', target);
} catch (e) {
  console.error('Ошибка восстановления:', e.message);
  process.exit(1);
}
