# Contributing

Contributions are welcome when they improve defensive, local-first analysis while preserving the application's safety boundaries. New rules should be explainable, narrowly scoped, tested with inert fixtures, and accompanied by a remediation recommendation. Do not submit malware samples, real credentials, proprietary documents, exploit chains, credential-recovery logic, evasive techniques, or code that executes a target.

Before opening a pull request, install the development extras and run:

```bash
python -m pytest
python -m compileall -q src tests
```

All documentation changes should preserve English and Spanish access where applicable. Please credit the project identity consistently: **Lumen AI**, GitHub **@villatorofidel6-alt**, and Discord **px1j**.

