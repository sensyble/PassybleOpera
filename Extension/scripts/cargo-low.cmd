@echo off
rem Runs cargo at idle CPU priority, so builds only use what other programs leave free.
rem Windows hands an idle priority down to child processes (rustc, the linker, build scripts).
rem   scripts\cargo-low.cmd test -p pass-core
start "" /b /wait /low cargo %*
exit /b %errorlevel%
