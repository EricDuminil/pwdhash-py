import unittest
import pwdhash
from io import StringIO
from unittest.mock import patch
from contextlib import redirect_stdout


class TestPwdHash(unittest.TestCase):
    def test_empty_pwdhash(self):
        # From https://pwdhash.github.io/website/
        self.assertEqual(pwdhash.pwdhash('example.com', ''), '2MPb')
        self.assertEqual(pwdhash.pwdhash('lemonde.fr', ''), 'u3CO')

    def test_pwdhash1_with_domains(self):
        # From https://pwdhash.github.io/website/
        tests = [
            ('lemonde.fr', 'p4ssw0rd', '1yGMAaKpbU'),
            ('skype.com', 'foo', 'v0F0B'),
            ('google.com', 'a l0ng p4assw0rd', 'paZTVGZwtewiq1+uCk'),
            ('google.com', 'qwertyuiop0987654321', 'nRDL7WNyFODhF29gAkNmpA'),
            ('google.com', 'qwertyuiop0987654321bingo', 'edi6wHWRQVA1rK8o9zaluwAAAA'),
            ('thetimes.co.uk', 'foobar', '8JyURsRs'),

        ]
        for domain, pwd, result in tests:
            self.assertEqual(pwdhash.pwdhash(domain, pwd), result, f'Hash for "{pwd}" on {domain} should be "{result}".')

    def test_pwdhash1_with_urls(self):
        # From https://pwdhash.github.io/website/
        tests = [
            ('https://mail.google.com', 'test', 'IeTLK1'),
            ('https://mail.google.com', '8mWEhXZTzQ2ZdGr', '4ITyeiNDa5plZLjKI'),
            ('https://github.com/EricDuminil/pwdhash-py',
             'correcthorsebatterystaple', 'FOrUIhAoAnqztACaG1Dk9AAAAA'),
            ('https://www.whatever.skype.com', 'foo', 'v0F0B'),
            ('https://images.google.com', 'a l0ng p4assw0rd', 'paZTVGZwtewiq1+uCk'),
            ('http://google.com', 'qwertyuiop0987654321', 'nRDL7WNyFODhF29gAkNmpA'),
            ('https://news.google.com', 'qwertyuiop0987654321bingo', 'edi6wHWRQVA1rK8o9zaluwAAAA'),
            ('https://www.thetimes.co.uk/', 'foobar', '8JyURsRs'),
        ]
        for url, pwd, result in tests:
            self.assertEqual(pwdhash.pwdhash(pwdhash.extract_domain(url), pwd), result,
                             f'Hash for "{pwd}" on {url} should be "{result}".')

class TestPwdHash2(unittest.TestCase):
    def test_pwdhash2_with_urls(self):
        # expected results calculated with https://gwuk.github.io/PwdHash2/pwdhash2/
        tests = [['5YrAI', 'foo', 10000, 'SomeSalt', 'https://www.skype.com/en/'],
          ['r8oIM4CR', 'foobar', 1, 'ChangeMe', 'https://google.com'],
          ['3PvCifzNoYaTNBMcJzVvDfDBeVK', 'correcthorsebatterystaple', 50000, 'COVwVNWVhwCsd7vlQ2T5BuIJBccYCu1RzR8rQFVHYVkGVQkZXHLkglnttWFQJYIN', 'https://about.google/intl/en/?fg=1&utm_source=google-EN&utm_medium=referral&utm_campaign=hp-header'],
          ['APC8mNJI', 'foobar', 1000, 'ChangeMe', 'https://google.com'],
        ]
        for expected, pwd, iterations, salt, url in tests:
            self.assertEqual(pwdhash.pwdhash2(pwdhash.extract_domain(url), pwd, iterations, salt), expected,
                             f'Hash for "{pwd}" on {url} ({salt}, *{iterations}) should be "{expected}".')

    def test_pwdhash2_collisions(self):
        tests = [
          ['foo', 1000, 'bar', 'https://manifolds.org', 'https://boxwoods.com'],
          ['foo', 50_000, 'aYcErTYgi0AoB2tDbP80fwR5GAWwUvg8', 'http://dainty.co.uk', 'http://polemic.com'],
          ['foobar', 100, 'salt', 'https://abounds.edu.au', 'https://coaxed.co.nz'],
        ]
        for pwd, iterations, salt, url1, url2 in tests:
            self.assertEqual(pwdhash.pwdhash2(pwdhash.extract_domain(url1), pwd, iterations, salt),
                pwdhash.pwdhash2(pwdhash.extract_domain(url2), pwd, iterations, salt))


class TestPwdHashCLI(unittest.TestCase):
    def call_cli(self, *args, stdin):
        fake_stdout = StringIO()
        with redirect_stdout(fake_stdout):
            with patch('sys.stdin', StringIO(stdin)):
                pwdhash.main(args)
        return fake_stdout.getvalue()

    def test_cli_pwdhash(self):
        self.assertEqual(self.call_cli(
            '--stdin', 'https://maps.google.com', stdin='test'), 'IeTLK1\n')
        self.assertEqual(self.call_cli(
            '--stdin', '-n', 'google.com', stdin='test'), 'IeTLK1')

    def test_cli_pwdhash_to_clipboard(self):
        import pyperclip
        pyperclip.copy('wrong')
        self.assertEqual(self.call_cli(
            '--stdin', '-c', 'google.com', stdin='12345'), '')
        self.assertEqual(pyperclip.paste(), 'lVOiR3j')


if __name__ == '__main__':
    unittest.main()
