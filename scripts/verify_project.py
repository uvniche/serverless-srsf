#!/usr/bin/env python3
"""Run local project checks and retain expected/actual verification outcomes.

This is local implementation evidence, not an AWS deployment or handover sign-off.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))


class RecordingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = []

    def record(self, test, actual, detail=None):
        self.records.append({'check': test.id(), 'expected': 'pass', 'actual': actual, 'detail': detail})

    def addSuccess(self, test):
        super().addSuccess(test); self.record(test, 'pass')

    def addFailure(self, test, err):
        super().addFailure(test, err); self.record(test, 'fail', self._exc_info_to_string(err, test))

    def addError(self, test, err):
        super().addError(test, err); self.record(test, 'error', self._exc_info_to_string(err, test))

    def addSkip(self, test, reason):
        super().addSkip(test, reason); self.record(test, 'not_run', reason)


def command_check(name, command, expected='exit 0'):
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
    return {'check': name, 'expected': expected, 'actual': 'pass' if result.returncode == 0 else 'fail',
            'exit_code': result.returncode, 'detail': result.stdout + result.stderr}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'verification-output' / 'local-checks.json')
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'))
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=RecordingResult).run(suite)
    checks = list(result.records)
    checks.append(command_check('python-compilation', [sys.executable, '-m', 'compileall', '-q', 'src', 'scripts']))
    env = dict(os.environ, PYTHONPATH=str(ROOT / 'src'))
    gate = subprocess.run([sys.executable, str(ROOT / 'scripts/srsf_gate.py'),
        str(ROOT / 'policies/f2-snapshot.json'), str(ROOT / 'policies/f2-snapshot.json'),
        '--catalogue', str(ROOT / 'policies/f2-catalogue.json')], cwd=ROOT, env=env, text=True, capture_output=True)
    checks.append({'check': 'bounded-iam-fixture', 'expected': 'cleared-within-coverage',
                   'actual': 'pass' if gate.returncode == 0 else 'fail',
                   'exit_code': gate.returncode, 'detail': gate.stdout + gate.stderr})
    lint = shutil.which('cfn-lint')
    if lint:
        checks.append(command_check('infrastructure-lint', [lint, 'template.yaml']))
    else:
        checks.append({'check': 'infrastructure-lint', 'expected': 'exit 0', 'actual': 'not_run',
                       'detail': 'cfn-lint is not installed'})
    snapshots = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in sorted(ROOT.glob('src/reference_app/**/*.py'))}
    for path in [ROOT / 'template.yaml', ROOT / 'pyproject.toml',
                 *sorted((ROOT / 'policies').glob('*.json')), *sorted((ROOT / 'tests').glob('*.py')),
                 *sorted((ROOT / 'scripts').glob('*.py'))]:
        snapshots[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    report = {'schema': 'ssrsf.project-verification.v1', 'timestamp': datetime.now(timezone.utc).isoformat(),
              'framework': 'Serverless Site Reliability and Security Framework',
              'scope': 'local tests, finite IAM fixtures, compilation and optional infrastructure lint',
              'runtime': platform.python_version(), 'platform': platform.platform(),
              'provider': 'AWS target; local in-memory adapters', 'region': 'not deployed',
              'configuration_sha256': snapshots, 'checks': checks,
              'unresolved_checks': [c['check'] for c in checks if c['actual'] != 'pass'],
              'deployment_verification': 'pending', 'performance_measurements': 'pending',
              'owner_acceptance': 'pending', 'operational_handover': 'pending'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(stream.getvalue(), end='')
    print(f'Verification record: {args.output}')
    return 1 if any(c['actual'] in ('fail', 'error') for c in checks) or not result.wasSuccessful() else 0


if __name__ == '__main__':
    raise SystemExit(main())
