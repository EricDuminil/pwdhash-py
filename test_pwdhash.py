import unittest
import pwdhash


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

if __name__ == '__main__':
    unittest.main()
