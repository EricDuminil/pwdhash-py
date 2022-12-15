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

    def test_pwdhash1(self):
        # From https://pwdhash.github.io/website/
        tests = [
                ('https://mail.google.com', 'test', 'IeTLK1'),
                ('https://mail.google.com', '8mWEhXZTzQ2ZdGr', '4ITyeiNDa5plZLjKI'),
                ('https://github.com/EricDuminil/pwdhash-py', 'correcthorsebatterystaple', 'FOrUIhAoAnqztACaG1Dk9AAAAA'),
                ('lemonde.fr', 'p4ssw0rd', '1yGMAaKpbU'),
                ]
        for url, pwd, result in tests:
            self.assertEqual(pwdhash.pwdhash(pwdhash.extract_domain(url), pwd), result,
                             f'Hash for "{pwd}" on {url} should be "{result}".')

    def call_cli(self, *args, stdin):
        fake_stdout = StringIO()
        with redirect_stdout(fake_stdout):
            with patch('sys.stdin', StringIO(stdin)):
                pwdhash.main(args)
        return fake_stdout.getvalue()


    def test_cli_pwdhash(self):
        self.assertEqual(self.call_cli('--stdin', 'https://maps.google.com', stdin='test'), 'IeTLK1\n')
        self.assertEqual(self.call_cli('--stdin', '-n', 'google.com', stdin='test'), 'IeTLK1')

    def test_cli_pwdhash_to_clipboard(self):
        import pyperclip
        pyperclip.copy('wrong')
        self.assertEqual(self.call_cli('--stdin', '-c', 'google.com', stdin='12345'), '')
        self.assertEqual(pyperclip.paste(), 'lVOiR3j')


if __name__ == '__main__':
    unittest.main()
