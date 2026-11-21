# Existing Project-current source import — normal invocation and native readiness

**Source owner:** host-deploy Regular, November 21, 2026
**Integrated base:** protected Task C owner / incomplete Gateway recovery (host-deploy PR #53)
**Producer installed for native readiness:** image-build PR #31,
`bce80b258e445191248d9998620884a79f029013`.

## Native failure and supported correction

The selected existing Project is **certbot-seed**, with normal interpreter
`/usr/bin/python3.12`. The image-build PR #31 checkout was installed in
that Project, with its active `kind=image` compiler generation unchanged.
However, a plain interpreter import of
`zog.image_build.remote_operations` resolved from
`/usr/lib/python3.12/site-packages`, not from the selected Project's
`source/src/zog/image_build/remote_operations.py`. Thus that plain
readiness invocation cannot prove that the next normal Project-current
producer uses PR #31.

**Reason:** the selected image-build checkout supplies a PEP 420-style
`src/zog` namespace. An installed *regular* `zog` package can shadow
it even with the Project source at the front of `PYTHONPATH`. Changing
the global interpreter environment or replacing installed dependencies
is not an appropriate correction.

The supported **host-deploy Project-current invocation** runs the
selected `python_executable` with `-I -B -c` and explicitly builds the
`zog` namespace with precedence:

1. This same Project's `source/src/zog` image-build checkout;
2. Project-local `companions/build-record/src/zog` and
   `companions/box-control/box-control/src/zog`, where they exist;
3. Installed `zog` components for remaining dependencies, plus ordinary
   Python site-packages for installed third-party distributions.

Before importing the producer, it independently resolves the selected
image-build `__init__.py` and `remote_operations.py` to their exact
Project paths. Project-local companions with their own package sources
must also resolve to their exact Project files; a missing/broken selected
companion cannot silently fall back to the installed one. After import,
the actual module `__file__` must still be the selected Project file.
No other Project is searched, and the original checkout/current package
pins are read by the normal producer.

## A read-only test of precisely the same import path

Both **actual dispatch** and **readiness** now reuse the single
`project_current._PROJECT_IMPORT_BOOTSTRAP`. The readiness form
imports the selected `remote_operations` module but deliberately
does not call its `main()`, construct a producer request, write a
`gateway-requests` directory, submit via box/root-control, or invoke
SSM SendCommand.

The supported source helper is:

```python
from zog.host_deploy.gateway.project_current import read_only_import_script

# Obtain PROJECT_ROOT from the existing authenticated, selected certbot-seed
# lane/controller record. Do not guess a path or create a replacement Project.
script = read_only_import_script(PROJECT_ROOT, "/usr/bin/python3.12")
# Execute this READ-ONLY command through the existing approved Host inspection
# path; never send the Project-current pipeline.submit script for readiness.
```

The emitted command uses that interpreter and the source-first bootstrap
with `--inspect-only`. The bounded JSON report is:

```json
{
  "schema": "host-deploy-project-current-import-readiness-v1",
  "source_root": "<existing Project>/source",
  "project_root": "<existing Project>",
  "python_executable": "/usr/bin/python3.12",
  "image_build_package": "<existing Project>/source/src/zog/image_build/__init__.py",
  "remote_operations": "<existing Project>/source/src/zog/image_build/remote_operations.py",
  "companions": {
    "build-record": {"present": true, "origin": "<selected Project companion source>"},
    "box-control": {"present": true, "origin": "<selected Project companion source>"}
  },
  "mutation": false,
  "execution_authorized": false
}
```

Companions absent from the Project's explicit companion roots are reported
with `present: false` and may be resolved as separately reviewed installed
dependencies. No assumed companion presence is made authoritative by the
illustrative JSON example. Work must inspect the **actual** output.

Readiness should additionally verify the current clean image-build Git HEAD
equals PR #31, the exact selected Project/controller binding and accepted
compiler generation, required system dependencies and producer-source bytes.
This read-only import test proves import precedence, not the right to compile.

## Work installation and acceptance sequence

1. Review this integrated host-deploy source and its supported existing
   Project/current-controller/runtime selections. The earlier installed
   host-deploy source was PR #47 `919e63bf9cc17f8184d0f81c147b71fe6a2c8d6f`,
   which does **not** contain PR #48's isolated import fix. Do not treat an
   older installed CLI as an accepted replacement because the Project
   image-build checkout was updated.
2. Install and attest the **reviewed integrated host-deploy source** without
   discarding the protected Task C send-once owner, incomplete-request
   handling, current Project companion bindings, or the installed
   image-build dependencies. Verify that the generated normal producer
   command contains `python -I -B -c` with the reviewed bootstrap.
3. Via an authorized **read-only inspection**, run the generated
   `read_only_import_script` against the existing **certbot-seed**
   Project using its actual selected root and `/usr/bin/python3.12`.
   Confirm both image-build paths point to that Project, companion origins
   are correct, and the selected import is not from
   `/usr/lib/python3.12/site-packages`. Preserve normal dependency imports.
   The selected image-build source revision must still be
   `bce80b258e445191248d9998620884a79f029013`.
4. Rerun the established *read-only* native readiness: selected Project,
   active `kind=image` input generation and original accepted receipt,
   controller, zlib/bzip2 development files, Expat, pkgconf/pkg-config,
   Bash/linker, source SHA/pins and complete Fonts stage selection.
5. Keep the original failed `acl: catalogue-only` request and its
   operation/receipt **unchanged**. Do **not** reuse its ID, replay it,
   resume the historical submission, enable the GitHub webhook or start
   a new Fonts compilation by running the producer command as a readiness
   probe. A future first executable Fonts request requires separate
   explicit authorization after native acceptance.

The source regressions create a disposable Python venv containing a
hostile installed regular `zog` package and ordinary third-party
dependencies. They prove the selected Project module wins, Project
companions remain available, installed dependencies remain usable, and
inspection does not create a gateway request. Missing/redirected Project
source and incomplete companions fail closed. The existing Task C owner
and send-once tests remain included. Source CI is not native acceptance.
