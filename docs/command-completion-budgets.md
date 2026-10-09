# Command completion budgets

Each successful leaf returns an explicit execution-only budget. Dispatch preserves it, and the top level warns only when elapsed time strictly exceeds it after output (including output errors). DEBUG dispatch/completion and the command span are independent of the receipt. JSON, CSV, text, HTML and planning data are unchanged.

- Plan create: 3 seconds for validating and writing one metadata file.
- Plan list: 3 seconds + 20 ms per returned plan for parsing and rendering a finite directory inventory.
- Plan show and action add/remove: 3 seconds + 1 ms per input KiB + 20 ms per action for parsing, validation and metadata revisions.
- Action list: the same per-action formula; action show: 3 seconds + input KiB + 20 ms for the selected action.
- Dry-run: 3 seconds + 1 ms per input KiB + 1 ms per squared action count, reflecting ordered pairwise dependency/conflict inspection. It does not execute moves.
- A plan read from `-`, or an action request read from `-`, deliberately returns None: interactive stdin can wait for the user indefinitely. File input remains finite.

The formulas use work size, never measured elapsed time. Arithmetic saturates. Input metadata inspection is read-only; no progress-event schema is required.