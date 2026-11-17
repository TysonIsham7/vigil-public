# Fixtures

These trees are detection samples. The scanner and the tests read them as text. They are not a project environment.

`deps/requirements.txt` pins LiteLLM 1.107.0 (MAL-2026-2144) and requests 2.32.3 so the dependency check can see those pins. Do not pass that file to a Python installer. Do not build `deps/Dockerfile`. Either one fetches a package the fixture is here to detect.

`scripts/fixture-install-guard.mjs` fails when a workflow, script, package script, or doc in this repo invokes a Python installer against a fixture requirements file. CI runs that script before any install step.
