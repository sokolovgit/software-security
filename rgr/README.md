# РГР: Аудит захищеності програмного застосунку

Варіант 19 – OWASP Juice Shop (Node.js/TypeScript), профіль **автентифікація**.
Дисципліна «Безпека програмного забезпечення», ФІОТ, 4 курс.

Наскрізний аудит над власною ізольованою ціллю: модель загроз → автоматизований
аналіз → ручне підтвердження вразливостей → усунення з регресійними тестами →
повторний прогін інструментів «до/після».

## Структура

| Каталог | Зміст |
|---|---|
| `docs/report/` | звіт (`report.md` → `.docx` → `.pdf`), діаграми в `assets/` |
| `env/` | `docker-compose.yml` – ізольоване розгортання цілі |
| `threat-model/` | артефакти моделі загроз |
| `exploits/` | `run_exploits.sh`, `forge_jwt.py`, докази в `evidence/` |
| `scanning/` | `scan.sh`, `gitleaks.toml`, `cvss.py` |
| `fixes/` | виправлення у вигляді патчів (`*.patch`) |
| `tests/` | `regression.sh` – регресійний набір |
| `reports/before`, `reports/after` | звіти інструментів і регресії «до/після» |
| `apply-fixes.sh` | відтворення цілі з виправленнями |

> `upstream/` (код цілі з node_modules, ~1 ГБ) не комітиться; відтворюється
> скриптом `apply-fixes.sh` з позначки `v20.4.0` + патчі з `fixes/`.

## Підтверджені вразливості

| № | Вразливість | CWE | CVSS |
|---|---|---|---|
| V1 | Обхід автентифікації (SQLi) | CWE-89 | 9.8 |
| V2 | Підробка JWT жорстко закодованим ключем | CWE-321, CWE-347 | 9.8 |
| V3 | Слабке гешування паролів (MD5) | CWE-916, CWE-759 | 4.4 |
| V4 | Відсутнє обмеження частоти (брутфорс) | CWE-307 | 6.5 |
| V5 | Зміна пароля без поточного | CWE-620 | 8.1 |
| V6 | Відсутнє відкликання сесій | CWE-613 | 7.4 |

## Відтворення

```sh
# 1. Розгорнути вразливу ціль ізольовано
docker compose -f env/docker-compose.yml up -d          # або: docker run -d -p 127.0.0.1:3000:3000 bkimminich/juice-shop:v20.4.0

# 2. Підтвердити вразливості (докази -> exploits/evidence/)
TARGET=http://127.0.0.1:3000 bash exploits/run_exploits.sh

# 3. Автоматизований аналіз
scanning/scan.sh upstream reports/before

# 4. Відтворити середовище з виправленнями і зібрати
./apply-fixes.sh
PORT=3001 NODE_ENV=unsafe node upstream/build/app.js &

# 5. Регресія до/після (0/6 на вразливому, 6/6 на виправленому)
TARGET=http://127.0.0.1:3001 bash tests/regression.sh

# 6. Повторний аналіз
scanning/scan.sh upstream reports/after
```

## Збірка звіту

```sh
python3 ~/.claude/skills/kpi-lab-report/scripts/render_diagram.py threat-model/dfd.mmd.md --name 01_dfd.png  # перерендерити DFD
just report Соколов_О_В_ІП-33_РГР.docx
```
