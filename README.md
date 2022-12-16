# PwdHash 1 and 2, in Python

This is a Python implementation of [*PwdHash*](http://pwdhash.com/) and [*PwdHash2*](https://gwuk.github.io/PwdHash2/), accessible from the command line.

It is function-equivalent to the original *PwdHash* browser add-on, as well as the updated version.

## Usage

```bash
❯ ./pwdhash.py -h
usage: pwdhash.py [-h] [-v {1,2}] [-s] [-c] [--salt SALT] [--iterations ITERATIONS] [-n] domain

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

## Examples

Standard PwdHash is calculated by default. Domain name is required as an argument, and password is entered in a prompt, without being displayed :

```bash
❯ python pwdhash.py example.com
Password: 
4kydhtBD9M
```

###  `--stdin`

It's possible to get the password from standard input. It displays the password if entered by the user:

```bash
❯ python pwdhash.py --stdin example.com
p4ssw0rd
4kydhtBD9M
```

but it allows to get the password from a pipe or a file:

```bash
❯ python pwdhash.py --stdin example.com < password
4kydhtBD9M
❯ cat password | python pwdhash.py --stdin example.com
4kydhtBD9M
❯ echo "p4ssw0rd" | python pwdhash.py --stdin example.com
4kydhtBD9M
```

###  `--copy`

It's possible to copy the password directly to the clipboard. It requires the `pyperclip` module. The password isn't displayed at all.

```bash
❯ ./pwdhash.py --stdin --copy example.com < password
```