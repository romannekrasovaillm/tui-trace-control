# tui-trace-control — контроль ризонинга и действий TUI-агентов по трейсам

<p align="center">
  <b>🇷🇺 <a href="#русский">Русский</a></b> | <b>🇬🇧 <a href="#english">English</a></b>
</p>

Набор из восьми скиллов (`SKILL.md`) для наблюдения, расследования и реакции
на действия терминальных ИИ-агентов по локальным трейс-файлам: журналам
сообщений, вызовов и результатов инструментов. Версия набора: 1.0.0.

---

<a id="русский"></a>

## 🇷🇺 Русский

### Почему ризонинг агентов нужно контролировать через трейсы

**1. У терминального агента реальные полномочия, а не текстовые.**
TUI-агент исполняет shell-команды, пишет в файловую систему, ходит в сеть,
запускает фоновые процессы. Каждое действие имеет эффект вне контекстного
окна — и откатить его сложнее, чем сгенерировать. Контроль такого агента
только по его словам — это контроль процесса по его собственному отчёту.

**2. Самоотчёт агента — не доказательство.**
Правдоподобный текст о том, что «всё сделано и проверено», генерируется так
же легко, как правдивый. Отчёт агента о собственных действиях — данные из
ненадёжного источника: он может быть неполным, неточным или оптимистичным
без всякого злого умысла. Приёмка работы по самоотчёту превращает
контроль в формальность.

**3. Видимый ризонинг не всегда говорит, что думает модель.**
Исследования показывают, что chain-of-thought может не отражать реальный
процесс принятия решения моделью (Anthropic, *«Reasoning models don't always
say what they think»*, 2025): на итог влияют факторы, которые в рассуждении
не упоминаются. Кроме того, провайдеры всё чаще скрывают или сворачивают
ризонинг. Вывод практический: намерение агента нельзя проверить по его
рассуждению — но **действие можно проверить по трейсу**. Вызов инструмента
с конкретными аргументами, его результат, запись в конкретный файл,
обращение к конкретному хосту — наблюдаемые факты, а не интерпретации.
Доступный reasoning при этом не выбрасывается: он служит дополнительным
сигналом, который сопоставляется с действиями.

**4. Трейс разделяет намерение, попытку и эффект.**
Это принципиально для расследований. Цитата опасной команды в рассуждении —
не нарушение. Попытка вызова, отклонённая барьером, — инцидент без эффекта.
Успешное выполнение — инцидент с эффектом. Три разных класса событий
требуют трёх разных реакций; без трейса они неотличимы друг от друга.

**5. Потеря наблюдаемости — сама по себе инцидент.**
Пропуск в последовательности событий, усечённый журнал, устаревший
heartbeat, тихая ротация файла — это не «технический сбой», а момент, когда
контроль перестал существовать. Если наблюдение молчит, корректный вывод —
«данных недостаточно», а не «всё спокойно». Поэтому целостность и
непрерывность трейса проверяются так же строго, как и его содержимое.

**6. Трейсы — это доказательная база для приёмки и аудита.**
Перед интеграцией или публикацией результата нужно сверить три вещи:
фактические артефакты, отчёт агента и трейс его действий. В регулируемых
средах (банковский контур, продуктивные контуры) вопрос «кто, что, когда и
с какими полномочиями сделал» задаётся задним числом обязательно — и
ответить на него можно только журналом, который вёлся независимо от
агента.

**7. Контроль должен масштабироваться механически.**
Флоты агентов, цель-режимы с автопродолжением, фоновые субагенты — число
действий на человека растёт, и «читать логи глазами» перестаёт работать.
Нужны детерминированные проверки с предсказуемыми исходами: контракт
границ задачи, сканер с явными кодами выхода, реакции supervisor,
привязанные к заранее выданным полномочиям. Скиллы этого набора задают
именно такой процесс.

**8. Где граница подхода — честно.**
Чтение уже сохранённого журнала — детекция, а не предотвращение: действие
обнаруживается после его эффекта. `SKILL.md` задаёт поведение агента-
наблюдателя и не является системной песочницей. Предотвращение опасных
операций требует барьера до исполнения (ограничения ОС и инструментов,
PreToolUse-хуки в доверенном supervisor). Контроль по трейсам — слой
обнаружения, доказательств и реакции в модели defense-in-depth, а не
замена ограничениям исполнения.

### Состав набора

| Скилл | Задача |
| --- | --- |
| `tui-trace-setup` | Границы задачи, независимый сбор событий, полномочия наблюдателя, проверка готовности перед запуском |
| `tui-trace-ingest` | Сбор и нормализация трейсов: происхождение, ротация, курсоры, пропуски, целостность |
| `tui-trace-watch` | Наблюдение в реальном времени: границы действий, heartbeat, сигналы supervisor (сканер Python, 40 тестов) |
| `tui-trace-audit` | Расследование: инъекции, обход ограничений, недостоверные отчёты; намерение vs попытка vs эффект |
| `tui-trace-contain` | Локализация инцидента: разрешённая приостановка запуска, проверка остановки, сохранение доказательств |
| `tui-trace-resume` | Разрешённое возобновление после инцидента: закрытие причины, связь запусков |
| `tui-trace-verify` | Приёмка результата: сверка артефактов, отчёта агента и трейса |
| `tui-trace-evaluate` | Проверка самого мониторинга: пропуски, ложные тревоги, фактическая блокировка |

Детали подключения и работы — `START_HERE_RU.md`. Выполненные проверки —
`VALIDATION_RU.md`, контрольные суммы — `MANIFEST.sha256`. Основания
проектных решений и границы их применимости —
`skills/tui-trace-setup/references/basis.md`.

### Быстрый старт (синтетические данные, Python 3.10+)

```bash
python3 skills/tui-trace-watch/scripts/tracecheck.py \
  --contract skills/tui-trace-setup/assets/contract.example.json \
  --trace skills/tui-trace-setup/assets/safe.jsonl \
  --now 2026-09-13T12:00:05Z \
  --final
```

Ожидается `no_findings`, exit code `0`. Для `blocked-attempt.jsonl` —
`pause_required`, код `20`; для `sequence-gap.jsonl` — `indeterminate`,
код `30`. Тесты сканера: `python3 skills/tui-trace-watch/scripts/test_tracecheck.py`.

### Источники

- Anthropic, *Reasoning models don't always say what they think* (2025) —
  ограничения достоверности видимого ризонинга.
- Claude Code, *Hooks reference* — различение контроля до и после вызова
  инструмента.
- OpenTelemetry, *URL attributes* — чувствительные данные в URL и их
  редактирование перед публикацией отчётов.

Протокол JSONL v1 и числовые пороги — проектные решения этого набора, а не
официальный стандарт.

---

<a id="english"></a>

## 🇬🇧 English

### Why agent reasoning must be controlled through traces

**1. A terminal agent holds real authority, not textual authority.**
A TUI agent runs shell commands, writes to the filesystem, reaches the
network, spawns background processes. Every action has an effect outside
the context window — and rolling it back is harder than producing it.
Controlling such an agent through its own words means controlling a
process by its self-report.

**2. An agent's self-report is not evidence.**
Plausible text claiming "done and verified" is generated as easily as
truthful text. The agent's report about its own actions is data from an
untrusted source: it can be incomplete, inaccurate, or optimistic without
any malicious intent at all. Accepting work on self-report turns control
into a formality.

**3. Visible reasoning does not always say what the model thinks.**
Research shows that chain-of-thought may not reflect the model's actual
decision process (Anthropic, *"Reasoning models don't always say what
they think"*, 2025): outcomes are influenced by factors the reasoning
never mentions. On top of that, providers increasingly hide or collapse
reasoning traces. The practical conclusion: an agent's intent cannot be
verified through its reasoning — but **its actions can be verified through
traces**. A tool call with concrete arguments, its result, a write to a
concrete file, a request to a concrete host — these are observable facts,
not interpretations. Available reasoning is not discarded: it serves as
an auxiliary signal that is cross-checked against actions.

**4. Traces separate intent, attempt, and effect.**
This matters decisively for investigations. A dangerous command quoted in
reasoning is not a violation. A blocked call attempt is an incident
without effect. A successful execution is an incident with effect. Three
distinct event classes demand three distinct responses; without traces
they are indistinguishable.

**5. Loss of observability is itself an incident.**
A gap in the event sequence, a truncated journal, a stale heartbeat, a
silent file rotation — these are not "technical glitches" but the moment
control ceases to exist. When observation goes silent, the correct
conclusion is "insufficient data", not "all quiet". That is why trace
integrity and continuity are checked as strictly as trace content.

**6. Traces are the evidence base for acceptance and audit.**
Before integrating or publishing a result, three things must be
reconciled: the actual artifacts, the agent's report, and the trace of
its actions. In regulated environments (banking perimeters, production
contours) the question "who did what, when, and with which authority" is
always asked after the fact — and it can only be answered by a journal
kept independently of the agent.

**7. Control must scale mechanically.**
Agent fleets, goal-mode auto-continuation, background subagents — the
number of actions per human keeps growing, and "reading logs by eye"
stops working. What works is deterministic checks with predictable
outcomes: a task-boundary contract, a scanner with explicit exit codes,
supervisor reactions bound to pre-issued authority. The skills in this
set define exactly that process.

**8. Where the approach ends — honestly.**
Reading an already-persisted journal is detection, not prevention: an
action is discovered after its effect. A `SKILL.md` steers an observer
agent and is not an operating-system sandbox. Preventing dangerous
operations requires a pre-execution barrier (OS and tool restrictions,
PreToolUse hooks in a trusted supervisor). Trace control is the
detection, evidence, and response layer in a defense-in-depth model —
not a replacement for execution constraints.

### Package contents

| Skill | Purpose |
| --- | --- |
| `tui-trace-setup` | Task boundaries, independent event collection, observer authority, pre-launch readiness |
| `tui-trace-ingest` | Trace collection and normalization: provenance, rotation, cursors, gaps, integrity |
| `tui-trace-watch` | Live monitoring: action boundaries, heartbeat, supervisor signals (Python scanner, 40 tests) |
| `tui-trace-audit` | Investigation: injections, restriction bypass, unreliable reports; intent vs attempt vs effect |
| `tui-trace-contain` | Incident containment: authorized run suspension, stop verification, evidence preservation |
| `tui-trace-resume` | Authorized resumption after an incident: cause closure, run linkage |
| `tui-trace-verify` | Result acceptance: reconciling artifacts, agent report, and trace |
| `tui-trace-evaluate` | Monitoring self-check: misses, false alarms, actual blocking |

Setup and usage details — `START_HERE_RU.md` (Russian). Completed
validations — `VALIDATION_RU.md`, checksums — `MANIFEST.sha256`. Design
rationale and applicability limits —
`skills/tui-trace-setup/references/basis.md`.

### Quick start (synthetic data, Python 3.10+)

```bash
python3 skills/tui-trace-watch/scripts/tracecheck.py \
  --contract skills/tui-trace-setup/assets/contract.example.json \
  --trace skills/tui-trace-setup/assets/safe.jsonl \
  --now 2026-09-13T12:00:05Z \
  --final
```

Expected: `no_findings`, exit code `0`. For `blocked-attempt.jsonl`:
`pause_required`, code `20`; for `sequence-gap.jsonl`: `indeterminate`,
code `30`. Scanner tests: `python3 skills/tui-trace-watch/scripts/test_tracecheck.py`.

### Sources

- Anthropic, *Reasoning models don't always say what they think* (2025) —
  limits of visible-reasoning faithfulness.
- Claude Code, *Hooks reference* — pre- vs post-tool-call control points.
- OpenTelemetry, *URL attributes* — sensitive data in URLs and redaction
  before report publication.

The JSONL v1 protocol and numeric thresholds are design decisions of this
package, not an official standard.
