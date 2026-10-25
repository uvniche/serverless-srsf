from __future__ import annotations
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ssrsf.adapters import MemoryServices
from ssrsf.config import settings
from ssrsf.handlers import approval, purge_broker, extract
from ssrsf.security import ebe
from ssrsf.security.anomaly import multi_window_alerts, spending_summary
from ssrsf.security.iam import authorization_decision, compare_authorization
from ssrsf.security.purge_auth import issue, verify


class Sink:
    def __init__(self): self.records = []; self.fail = None
    def emit(self, record):
        if record['type'] == self.fail: raise RuntimeError('outage')
        self.records.append(record)
        return 'retained-version'


class EvidenceTests(unittest.TestCase):
    def test_ack_before_processing_and_compare_previous_exit(self):
        sink = Sink()
        with tempfile.TemporaryDirectory() as root:
            @ebe.instrument('test-serial', sink=sink, root=root)
            def handler(event, context):
                self.assertEqual(sink.records[-1]['type'], 'entry')
                Path(root, 'declared-cache').write_text('legitimate')
            handler({}, None)
            handler({}, None)
            self.assertFalse(sink.records[-2]['unexpected_delta'])
            Path(root, 'undeclared').write_text('changed between invocations')
            handler({}, None)
            self.assertTrue(sink.records[-2]['unexpected_delta'])
            self.assertEqual([r['sequence'] for r in sink.records if r['type'] == 'entry'], [1, 2, 3])

    def test_initial_manifest_and_application_logs_share_audit_correlation(self):
        sink = Sink(); output = io.StringIO()
        with tempfile.TemporaryDirectory() as root, patch('sys.stdout', output):
            @ebe.instrument('test-project-correlation', sink=sink, root=root)
            def handler(event, context):
                self.assertEqual(event['_ssrsf_correlation_id'], 'project-check-1')
            handler({'headers': {'x-correlation-id': 'project-check-1'}}, None)
        initialization = sink.records[0]
        self.assertEqual(initialization['manifest_sha256'], ebe._hash_json([]))
        self.assertEqual(initialization['manifest_entries'], [])
        application = [json.loads(line)['ssrsf_application'] for line in output.getvalue().splitlines()]
        self.assertEqual([r['type'] for r in application], ['processing_started', 'processing_finished'])
        self.assertTrue(all(r['correlation_id'] == initialization['correlation_id'] for r in application))

    def test_entry_failure_blocks_handler(self):
        sink = Sink(); sink.fail = 'entry'
        called = []
        with tempfile.TemporaryDirectory() as root, patch('ssrsf.security.ebe.time.sleep'):
            @ebe.instrument('test-entry-failure', sink=sink, root=root)
            def handler(event, context): called.append(True)
            with self.assertRaises(ebe.AuditUnavailable): handler({}, None)
            self.assertEqual(called, [])

    def test_exit_failure_is_gap_not_malicious_delta(self):
        sink = Sink(); sink.fail = 'exit'; called = []
        with tempfile.TemporaryDirectory() as root, patch('ssrsf.security.ebe.time.sleep'):
            @ebe.instrument('test-exit-failure', sink=sink, root=root)
            def handler(event, context): called.append(True)
            with self.assertRaises(ebe.AuditUnavailable): handler({}, None)
            self.assertEqual(called, [True])  # Side effects cannot be undone by exit failure.
            sink.fail = None
            handler({}, None)
            entry = sink.records[-2]
            self.assertTrue(entry['evidence_gap'])
            self.assertFalse(entry['unexpected_delta'])

    def test_content_hash_detects_metadata_preserving_change(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root, 'file'); p.write_text('one'); stat = p.stat()
            first = ebe.manifest(root); content_first = ebe.manifest(root, content=True)
            p.write_text('two')
            import os
            os.utime(p, ns=(stat.st_atime_ns, stat.st_mtime_ns))
            self.assertEqual(first[0], ebe.manifest(root)[0])
            self.assertNotEqual(content_first[0], ebe.manifest(root, content=True)[0])

    def test_conditional_s3_retry_has_same_key_and_receipt(self):
        class Client:
            def __init__(self): self.keys = []
            def put_object(self, **kwargs):
                self.keys.append(kwargs['Key'])
                self.kwargs = kwargs
                if len(self.keys) == 1: raise TimeoutError('ack lost')
                class Exists(Exception):
                    response = {'Error': {'Code': 'PreconditionFailed'}}
                raise Exists()
        client = Client(); sink = ebe.S3AuditSink('retained-audit', client)
        with patch('ssrsf.security.ebe.time.sleep'):
            receipt = ebe.acknowledge(sink, {'type': 'entry', 'idempotency_key': 'same-record'})
        self.assertTrue(receipt.startswith('evidence/'))
        self.assertEqual(client.keys[0], client.keys[1])
        self.assertEqual(client.kwargs['IfNoneMatch'], '*')


class AuthorizationTests(unittest.TestCase):
    def snapshot(self):
        return {'scope': 'same-account-role', 'principal': 'F2', 'identity': [{'Statement': [
            {'Effect': 'Allow', 'Action': 's3:GetObject', 'Resource': 'arn:raw/a'}]}],
            'resource': [], 'boundaries': [], 'session': [], 'organization': []}

    def request(self):
        return {'principal': 'F2', 'action': 's3:GetObject', 'resource': 'arn:raw/a', 'context': {}}

    def test_explicit_deny_and_boundary_intersection(self):
        s = self.snapshot(); r = self.request()
        self.assertEqual(authorization_decision(s, r), 'allow')
        s['boundaries'] = [{'Statement': [{'Effect': 'Allow', 'Action': 's3:PutObject', 'Resource': '*'}]}]
        self.assertEqual(authorization_decision(s, r), 'deny')
        s['boundaries'] = []
        s['identity'][0]['Statement'].append({'Effect': 'Deny', 'Action': 's3:*', 'Resource': '*'})
        self.assertEqual(authorization_decision(s, r), 'deny')

    def test_condition_removal_detects_expansion_but_requires_scope_review(self):
        s = self.snapshot(); candidate = copy.deepcopy(s)
        s['identity'][0]['Statement'][0]['Condition'] = {'StringEquals': {'team': 'operations'}}
        r = self.request(); r['context'] = {'team': 'other'}
        result = compare_authorization(s, candidate, [r])
        self.assertEqual(len(result['expansions']), 1)
        self.assertTrue(result['unresolved'])

    def test_missing_inputs_notaction_resource_policy_and_context_abstain(self):
        for mutation in ('missing', 'notaction', 'resource', 'condition'):
            s = self.snapshot()
            if mutation == 'missing': del s['organization']
            if mutation == 'notaction': s['identity'][0]['Statement'][0]['NotAction'] = 's3:DeleteObject'
            if mutation == 'resource': s['resource'] = [{'Statement': []}]
            if mutation == 'condition': s['identity'][0]['Statement'][0]['Condition'] = {'IpAddress': {'aws:SourceIp': '1.2.3.4'}}
            self.assertEqual(authorization_decision(s, self.request()), 'unresolved')

    def test_aws_wildcards_do_not_treat_brackets_as_shell_patterns(self):
        s = self.snapshot()
        s['identity'][0]['Statement'][0]['Resource'] = 'arn:raw/[ab]'
        r = self.request(); r['resource'] = 'arn:raw/a'
        self.assertEqual(authorization_decision(s, r), 'deny')
        r['resource'] = 'arn:raw/[ab]'
        self.assertEqual(authorization_decision(s, r), 'allow')

    def test_outside_catalogue_changes_do_not_clear(self):
        s = self.snapshot(); candidate = copy.deepcopy(s)
        candidate['identity'][0]['Statement'].append({'Effect': 'Allow', 'Action': 's3:DeleteObject', 'Resource': 'arn:raw/b'})
        self.assertTrue(compare_authorization(s, candidate, [self.request()])['unresolved'])


class BrokerTests(unittest.TestCase):
    def approved(self, svc):
        event = {'requestContext': {'authorizer': {'jwt': {'claims': {
            'sub': 'reviewer', 'cognito:groups': ['purge-approvers']}}}},
            'body': json.dumps({'document_id': 'd1', 'raw_key': 'incoming/d1/doc.pdf',
                                'raw_version': 'raw-v1', 'text_version': 'text-v1'})}
        result = approval.handle(event, None, svc)
        return {'purge_token': json.loads(result['body'])['purge_token']}

    def test_replay_rejected_and_recorded_completion(self):
        svc = MemoryServices(); event = self.approved(svc)
        purge_broker.handle(event, None, svc, Sink())
        with self.assertRaises(ValueError): purge_broker.handle(event, None, svc, Sink())
        operation = next(iter(svc.operations.values()))
        self.assertEqual(operation['status'], 'completed')
        self.assertEqual(operation['completed'], ['raw', 'text', 'row'])

    def test_self_issued_and_cross_requester_grants_rejected(self):
        svc = MemoryServices(); event = self.approved(svc)
        grant = verify(event['purge_token'], settings.purge_token_secret)
        for field, value in [('requester', 'substituted'), ('raw_key', 'incoming/other/file'), ('issuer', 'F4')]:
            altered = {**grant, field: value}
            token = issue(altered, settings.purge_token_secret)
            with self.assertRaises(ValueError): purge_broker.handle({'purge_token': token}, None, svc, Sink())
        self.assertEqual(svc.operations, {})

    def test_expired_grant_and_unavailable_approval_fail_closed(self):
        svc = MemoryServices(); event = self.approved(svc)
        with patch('ssrsf.security.purge_auth.time.time', return_value=10**12):
            with self.assertRaises(ValueError): purge_broker.handle(event, None, svc, Sink())
        svc.grants.clear()
        with self.assertRaises(ValueError): purge_broker.handle(event, None, svc, Sink())
        self.assertEqual(svc.operations, {})

    def test_partial_delete_requires_reconciliation_and_new_authorization(self):
        svc = MemoryServices(); event = self.approved(svc)
        def fail_delete(document): raise RuntimeError('DynamoDB outage')
        svc.delete_item = fail_delete
        with self.assertRaises(RuntimeError): purge_broker.handle(event, None, svc, Sink())
        operation = next(iter(svc.operations.values()))
        self.assertEqual(operation, {'completed': ['raw', 'text'], 'status': 'reconciliation_required'})
        with self.assertRaises(ValueError): purge_broker.handle(event, None, svc, Sink())

    def test_nonce_store_outage_prevents_credential_acquisition(self):
        svc = MemoryServices(); event = self.approved(svc)
        def outage(*args): raise RuntimeError('nonce store unavailable')
        svc.consume_nonce = outage
        with patch.object(svc, 'scoped_purge') as credentials:
            with self.assertRaises(RuntimeError): purge_broker.handle(event, None, svc, Sink())
            credentials.assert_not_called()

    def test_forged_signature_and_wildcard_target_rejected(self):
        svc = MemoryServices(); event = self.approved(svc)
        with self.assertRaises(ValueError): purge_broker.handle({'purge_token': event['purge_token'] + 'x'}, None, svc, Sink())
        grant = verify(event['purge_token'], settings.purge_token_secret)
        token = issue({**grant, 'raw_key': 'incoming/d1/*'}, settings.purge_token_secret)
        with self.assertRaises(ValueError): purge_broker.handle({'purge_token': token}, None, svc, Sink())


class CostTests(unittest.TestCase):
    def test_total_and_excess_use_distinct_denominators(self):
        result = spending_summary(144, 10, 1000)
        self.assertEqual(result['spend_multiplier'], 14.4)
        self.assertEqual(result['excess'], 134)
        self.assertEqual(result['total_cap'], 1300)
        self.assertEqual(result['excess_allowance'], 300)
        self.assertTrue(spending_summary(1, 0, 100)['unexpected_activity'])

    def test_both_windows_must_exceed_threshold(self):
        self.assertEqual(multi_window_alerts({'5m': (150, 10), '1m': (10, 10)}), [])
        self.assertEqual(multi_window_alerts({'5m': (150, 10), '1m': (150, 10)})[0]['action'], 'page')


class ParserTests(unittest.TestCase):
    def test_real_pdf_parser_and_cleanup(self):
        try:
            from pypdf import PdfWriter
        except ImportError:
            self.skipTest("pypdf is not installed")
        writer = PdfWriter(); writer.add_blank_page(width=100, height=100)
        stream = io.BytesIO(); writer.write(stream)
        svc = MemoryServices(); svc.objects[(settings.raw_bucket, 'incoming/pdf1/doc.pdf')] = stream.getvalue()
        extract.handle({'Records': [{'s3': {'bucket': {'name': settings.raw_bucket},
                     'object': {'key': 'incoming/pdf1/doc.pdf'}}}]}, None, svc)
        self.assertIn((settings.text_bucket, 'text/pdf1.txt'), svc.objects)
        self.assertFalse(Path(tempfile.gettempdir(), 'pdf1.stage').exists())


class ReconciliationTests(unittest.TestCase):
    def test_exit_sequence_and_independent_count_gaps(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('reconcile', Path(__file__).parents[1] / 'scripts/reconcile_evidence.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        records = [dict(function='F2', environment_id='env', invocation_id='a', sequence=1, type='entry'),
                   dict(function='F2', environment_id='env', invocation_id='a', sequence=1, type='exit'),
                   dict(function='F2', environment_id='env', invocation_id='c', sequence=3, type='entry')]
        gaps = module.reconcile(records, {'F2': 3})
        self.assertTrue(any(g.get('missing') == ['exit'] for g in gaps))
        self.assertTrue(any(g.get('missing_sequences') == [2] for g in gaps))
        self.assertTrue(any(g.get('provider_invocations') == 3 for g in gaps))
