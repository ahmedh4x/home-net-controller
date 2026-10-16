@echo off
title Home Net Controller Test Suite
echo Running Home Net Controller Pytest Suite...
python -m pytest -v "%~dp0..\tests"
pause
