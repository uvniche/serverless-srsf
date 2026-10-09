#!/usr/bin/env python3
"""Reconcile retained EBE records with independent per-function invocation counts.

Inputs must cover the same declared time window. Records are read by an operator
role, never by application functions. Provider counts reveal emitter suppression.
"""
import argparse
import json


def reconcile(records, independent_counts):
    invocations = {}
    sequences = {}
    for record in records:
        if record.get('type') not in ('entry', 'exit'):
            continue
        key = (record['function'], record['environment_id'], record['invocation_id'])
        invocations.setdefault(key, set()).add(record['type'])
        sequences.setdefault((key[0], key[1]), set()).add(record['sequence'])
    gaps = [{'function': key[0], 'environment_id': key[1], 'invocation_id': key[2],
             'missing': sorted({'entry', 'exit'} - phases)} for key, phases in invocations.items()
            if phases != {'entry', 'exit'}]
    for (function, environment), values in sequences.items():
        missing = sorted(set(range(min(values), max(values) + 1)) - values)
        if missing:
            gaps.append({'function': function, 'environment_id': environment, 'missing_sequences': missing})
    for function, expected in independent_counts.items():
        observed = sum(1 for key, phases in invocations.items() if key[0] == function and 'entry' in phases)
        if observed != expected:
            gaps.append({'function': function, 'provider_invocations': expected, 'retained_entries': observed})
    return gaps


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('records', help='JSON list of retained EBE records')
    parser.add_argument('provider_counts', help='JSON object of independent invocation counts')
    args = parser.parse_args()
    with open(args.records) as handle: records = json.load(handle)
    with open(args.provider_counts) as handle: counts = json.load(handle)
    gaps = reconcile(records, counts)
    print(json.dumps({'evidence_gaps': gaps}, sort_keys=True))
    return 2 if gaps else 0


if __name__ == '__main__':
    raise SystemExit(main())
