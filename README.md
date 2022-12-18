# PwdHash 1 and 2, in Python

This is a Python implementation of [*PwdHash*](http://pwdhash.com/) and [*PwdHash2*](https://gwuk.github.io/PwdHash2/), accessible from the command line.

It is function-equivalent to the original *PwdHash* browser add-on, as well as the updated version.

## Installation

`pip install pwdhash`

## Usage

Once installed with pip, `pwdhash` command should be available in the PATH.

If sources are available, the script can also be called with `python pwdhash.py` or `./pwdhash.py`.

```bash
❯ pwdhash -h
usage: pwdhash [-h] [-v {1,2}] [-s] [-c] [--salt SALT] [--iterations ITERATIONS] [-n] domain

Computes PwdHash1 or PwdHash2.

positional arguments:
  domain                the domain or uri of the site

optional arguments:
  -h, --help            show this help message and exit
  -v {1,2}, --version {1,2}
                        Use PwdHash 1 or 2. Default is 1
  -s, --stdin           Get password from stdin instead of prompt. Default is prompt
  -c, --copy            Copy hash to clipboard instead of displaying it. Default is display
  --salt SALT           Salt (for PwdHash 2)
  --iterations ITERATIONS
                        How many iterations (for PwdHash 2)
  -n                    Do not print the trailing newline
```

## PwdHash Examples

Standard PwdHash is calculated by default. Domain name is required as an argument, and password is entered in a prompt, without being displayed :

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
❯ pwdhash -v2 example.com
Exception: Please define 'PWDHASH2_SALT' environment variable, or specify --salt.
```
PwdHash2 requires a Salt:

```bash
❯ pwdhash -v2 example.com --salt ChangeMe
Exception: Please define 'PWDHASH2_ITERATIONS' environment variable, or specify --iterations.
```
and a number of iterations:
```bash
❯ pwdhash -v2 example.com --salt ChangeMe --iterations 50000
Password:
7qErBOIB6R
❯ pwdhash -v2 example.com --salt ChangeMe --iterations 50000 --stdin < password
7qErBOIB6R
```

### Environment variables

Salt and Iterations can also be specified as *environment variables*:

```bash
❯ PWDHASH2_SALT=ChangeMe PWDHASH2_ITERATIONS=50000 pwdhash -v2 example.com --stdin < password
7qErBOIB6R
```

If you define those variables inside your `.bashrc` or `.zshrc`, you don't need to specify them anymore:

```bash
❯ pwdhash -v2 example.com --stdin < password
7qErBOIB6R
```

## Authors

* Based on [Stanford PwdHash](https://pwdhash.github.io/website/)
* [Joost Rijneveld](https://github.com/joostrijneveld), 2015
* [Eric Duminil](https://github.com/EricDuminil), 2022
