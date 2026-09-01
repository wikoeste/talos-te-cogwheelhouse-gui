import unittest
from unittest.mock import Mock, patch

from liono.common import elasticqueries


class ElasticQueriesTests(unittest.TestCase):
    def test_all_standalone_query_modes_are_available(self):
        self.assertEqual(len(elasticqueries.public_specs()), 12)
        self.assertEqual(set(elasticqueries.SPEC_BY_KEY), {
            'submissions', 'sha256', 'domain_sdr', 'sender_email', 'sender_ip',
            'subject', 'message_id', 'uri', 'recipient_domain', 'recipient_email',
            'guid', 'etd_verdict',
        })

    def test_query_specific_validation(self):
        self.assertEqual(elasticqueries.validate_search('submissions', 'Analyst.1'), 'analyst.1@cisco.com')
        self.assertEqual(elasticqueries.validate_search('sender_ip', '2001:4860:4860::8888'), '2001:4860:4860::8888')
        self.assertEqual(elasticqueries.validate_search('recipient_domain', 'Example.COM.'), 'example.com')
        with self.assertRaises(elasticqueries.ElasticQueryValidationError):
            elasticqueries.validate_search('sha256', 'not-a-hash')
        with self.assertRaises(elasticqueries.ElasticQueryValidationError):
            elasticqueries.validate_search('message_id', 'unsafe*wildcard')

    def test_batch_limits_and_deduplicates(self):
        first = '123e4567-e89b-12d3-a456-426614174000'
        second = '123e4567-e89b-12d3-a456-426614174001'
        self.assertEqual(elasticqueries.validate_search('guid', f'{first}\n{first}\n{second}'), [first, second])
        with self.assertRaises(elasticqueries.ElasticQueryValidationError):
            elasticqueries.validate_search('etd_verdict', '\n'.join(f'cid{i}' for i in range(11)))

    def test_queries_use_structured_json_without_user_string_concatenation(self):
        value = 'alerts+sample@example.com'
        validated = elasticqueries.validate_search('sender_email', value)
        index, body = elasticqueries.build_query('sender_email', validated)
        self.assertEqual(index, 'juno_past_3_months')
        term = body['query']['nested']['query']['term']
        self.assertEqual(term, {'froms.address_raw': value})

    @patch('liono.common.elasticqueries.requests.get')
    def test_search_verifies_tls_and_normalizes_rows(self, request_get):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            'hits': {
                'total': {'value': 1},
                'hits': [{
                    '_id': 'cid123',
                    '_source': {
                        '@timestamp': '2026-08-24T10:00:00Z',
                        'category': 'spam',
                        'subject': '<unsafe-looking but escaped by Jinja>',
                    },
                }],
            },
        }
        request_get.return_value = response
        with patch.object(elasticqueries.settings, 'juno', 'https://prod-juno-search-api.sv4.ironport.com/'), \
             patch.object(elasticqueries.settings, 'junoKey', 'test-key'), \
             patch.object(elasticqueries.settings, 'uname', 'analyst'):
            result = elasticqueries.search('subject', 'Quarterly report')
        self.assertEqual(result['rows'][0]['cid'], 'cid123')
        self.assertEqual(result['total'], 1)
        _, kwargs = request_get.call_args
        self.assertTrue(kwargs['verify'])
        self.assertIsInstance(kwargs['json'], dict)
        self.assertEqual(kwargs['auth'], ('analyst', 'test-key'))

    def test_unapproved_endpoint_is_rejected(self):
        with patch.object(elasticqueries.settings, 'juno', 'https://example.com/'), \
             patch.object(elasticqueries.settings, 'junoKey', 'test-key'):
            with self.assertRaises(elasticqueries.ElasticQueryServiceError):
                elasticqueries.search('subject', 'Quarterly report')


if __name__ == '__main__':
    unittest.main()
