#!/usr/bin/env python3
"""Report per-function spend from operator-supplied, measured billing windows."""
import argparse
import json
from ssrsf.security.anomaly import multi_window_alerts, spending_summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', help='JSON list of function, observed, expected, monthly_baseline, windows')
    args = parser.parse_args()
    with open(args.input) as handle:
        functions = json.load(handle)
    for function in functions:
        print(json.dumps({'function': function['function'],
            'summary': spending_summary(function['observed'], function['expected'],
                function['monthly_baseline'], function.get('tolerance', .30)),
            'alerts': multi_window_alerts(function['windows'])}, sort_keys=True))


if __name__ == '__main__':
    main()
