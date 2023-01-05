# PwdHash 1 and 2, in Python

This is a Python implementation of [*PwdHash*](http://pwdhash.com/) and [*PwdHash2*](https://gwuk.github.io/PwdHash2/), accessible from the command line.

It is function-equivalent to the original *PwdHash* browser add-on, as well as the updated version.

It does not require any dependency, and should work on any Python 3.4+.

It includes many options, and should be easy to integrate into any workflow.

## Installation

`pip install pwdhash`

## Usage

Once installed with pip, `pwdhash` and `pwdhash2` commands should be available in the PATH.

### `pwdhash`

```bash
❯ pwdhash -h
usage: pwdhash [-h] [-s] [-t] [-c] [-n] domain

Computes PwdHash1

positional arguments:
  domain       the domain or uri of the site

optional arguments:
  -h, --help   show this help message and exit
  -s, --stdin  Get password from stdin instead of prompt. Default is prompt
  -t, --twice  Ask password twice, and check both are the same. Default is once
  -c, --copy   Copy hash to clipboard instead of displaying it. Default is display
  -n           Do not print the trailing newline
```
### `pwdhash2`

```bash
❯ pwdhash2 -h
usage: pwdhash2 [-h] [-s] [-t] [-c] [-n] [--salt SALT] [--iterations ITERATIONS] domain

Computes PwdHash2

positional arguments:
  domain                the domain or uri of the site

optional arguments:
  -h, --help            show this help message and exit
  -s, --stdin           Get password from stdin instead of prompt. Default is prompt
  -t, --twice           Ask password twice, and check both are the same. Default is once
  -c, --copy            Copy hash to clipboard instead of displaying it. Default is display
  -n                    Do not print the trailing newline
  --salt SALT           Salt
  --iterations ITERATIONS
                        How many iterations
```

### `python pwdhash.py`

If sources are available, the script can also be called with `python pwdhash.py` or `./pwdhash.py`.

```bash
❯ python pwdhash.py -h
usage: pwdhash.py [-h] [-s] [-t] [-c] [-n] [-v {1,2}] [--salt SALT] [--iterations ITERATIONS] domain

Computes PwdHash1 or PwdHash2

positional arguments:
  domain                the domain or uri of the site

optional arguments:
  -h, --help            show this help message and exit
  -s, --stdin           Get password from stdin instead of prompt. Default is prompt
  -t, --twice           Ask password twice, and check both are the same. Default is once
  -c, --copy            Copy hash to clipboard instead of displaying it. Default is display
  -n                    Do not print the trailing newline
  -v {1,2}, --version {1,2}
                        Use PwdHash 1 or 2. Default is 1
  --salt SALT           Salt
  --iterations ITERATIONS
                        How many iterations
```

## PwdHash Examples

Domain name is required as an argument, and password is entered in a prompt, without being displayed :

```bash
❯ pwdhash example.com
Password: 
4kydhtBD9M
```

###  `--stdin`

It's possible to get the password from standard input. It displays the password if entered by the user:

```bash
❯ pwdhash --stdin example.com
p4ssw0rd
4kydhtBD9M
```

but it allows to get the password from a pipe or a file:

```bash
❯ pwdhash --stdin example.com < password
4kydhtBD9M
❯ cat password | pwdhash --stdin example.com
4kydhtBD9M
❯ echo "p4ssw0rd" | pwdhash --stdin example.com
4kydhtBD9M
```

###  `--twice`

It's possible to ask for the password twice, in order to avoid typos:

```
❯ pwdhash --twice example.com
Password:
Enter password again:
ERROR: Passwords did not match.
```

`pwdhash` returns as usual if both passwords match:

```
❯ pwdhash --twice example.com
Password:
Enter password again:
4kydhtBD9M
```

###  `--copy`

It's possible to copy the password directly to the clipboard. It requires the [`pyperclip`](https://pypi.org/project/pyperclip/) module. The password isn't displayed at all.

```bash
❯ pwdhash --stdin --copy example.com < password
```

### `-n`

Passwords can also be displayed without trailing newline:

```bash
❯ pwdhash --stdin example.com -n < password
4kydhtBD9M%
```

## PwdHash2 Examples

```bash
❯ pwdhash2 example.com
Exception: Please define 'PWDHASH2_SALT' environment variable, or specify --salt.
```
PwdHash2 requires a Salt:

```bash
❯ pwdhash2 example.com --salt ChangeMe
Exception: Please define 'PWDHASH2_ITERATIONS' environment variable, or specify --iterations.
```
and a number of iterations:
```bash
❯ pwdhash2 example.com --salt ChangeMe --iterations 50000
Password:
7qErBOIB6R
❯ pwdhash2 example.com --salt ChangeMe --iterations 50000 --stdin < password
7qErBOIB6R
```

### Environment variables

Salt and Iterations can also be specified as *environment variables*:

```bash
❯ PWDHASH2_SALT=ChangeMe PWDHASH2_ITERATIONS=50000 pwdhash2 example.com --stdin < password
7qErBOIB6R
```

If you define those variables inside your `.bashrc` or `.zshrc`, you don't need to specify them anymore:

```bash
❯ pwdhash2 example.com --stdin < password
7qErBOIB6R
```

## Call from Python script

```python
import pwdhash

print(pwdhash.extract_domain('https://subdomain.example.com/folder'))
# example.com

print(pwdhash.pwdhash('example.com', 'p4ssw0rd'))
# 4kydhtBD9M

print(pwdhash.pwdhash2('example.com', 'p4ssw0rd', 50_000, 'ChangeMe'))
# 7qErBOIB6R
```

## Tests

```bash
❯ pytest -v
================================= test session starts ==================================
collected 15 items

test_pwdhash.py::TestPwdHash::test_empty_pwdhash PASSED                                        [  6%]
test_pwdhash.py::TestPwdHash::test_pwdhash1_with_domains PASSED                                [ 13%]
test_pwdhash.py::TestPwdHash::test_pwdhash1_with_urls PASSED                                   [ 20%]
test_pwdhash.py::TestPwdHash::test_pwdhash1_with_utf8 PASSED                                   [ 26%]
test_pwdhash.py::TestPwdHash2::test_pwdhash2_collisions PASSED                                 [ 33%]
test_pwdhash.py::TestPwdHash2::test_pwdhash2_edge_cases PASSED                                 [ 40%]
test_pwdhash.py::TestPwdHash2::test_pwdhash2_with_urls PASSED                                  [ 46%]
test_pwdhash.py::TestPwdHashCLI::test_cli_pwdhash PASSED                                       [ 53%]
test_pwdhash.py::TestPwdHashCLI::test_cli_pwdhash2 PASSED                                      [ 60%]
test_pwdhash.py::TestPwdHashCLI::test_cli_pwdhash_to_clipboard PASSED                          [ 66%]
test_pwdhash.py::TestPwdHashCLI::test_pwdhash_v1_script PASSED                                 [ 73%]
test_pwdhash.py::TestPwdHashCLI::test_pwdhash_v2_script PASSED                                 [ 80%]
test_pwdhash.py::TestInteractivePwdHash::test_input_password PASSED                            [ 86%]
test_pwdhash.py::TestInteractivePwdHash::test_input_password_no_newline PASSED                 [ 93%]
test_pwdhash.py::TestInteractivePwdHash::test_input_password_v2 PASSED                         [100%]

================================== 9 passed in 0.46s ===================================
```


## Authors

* Based on [Stanford PwdHash](https://pwdhash.github.io/website/)
* [Joost Rijneveld](https://github.com/joostrijneveld), 2015
* [Eric Duminil](https://github.com/EricDuminil), 2022
