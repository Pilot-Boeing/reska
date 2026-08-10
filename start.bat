@echo off
chcp 65001 >nul
title Space - запуск
cd /d "%~dp0"
if not exist node_modules (
  echo [1/2] Установка зависимостей...
  call npm install
  if errorlevel 1 (
    echo Основной реестр недоступен, пробую зеркало (npmmirror)...
    call npm install --registry=https://registry.npmmirror.com
    if errorlevel 1 (
      echo Ошибка установки. Проверьте, что установлен Node.js 22.5+ и есть интернет.
      pause
      exit /b 1
    )
  )
)
echo [2/2] Запуск сервера...
call npm start
pause
