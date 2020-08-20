This is an experimental attempt to "cross the gap" between Flask code and templates. It combines Semgrep queries and regular expressions to detect reflected XSS with high confidence. If this detects something, it's highly likely a reflected XSS.

## Try it out

```
$ pipenv shell
$ pipenv install
$ python xss_match/try_xss_match.py <your_flask_repo>
```

If you want to test it on, say, `https://github.com/minusworld/xss-demo`, clone it. The result would look like:

```
$ git clone https://github.com/minusworld/xss-demo
$ python xss_match/try_xss_match.py xss-demo/
running 1 rules...
running 2 rules...
100%|███████████████████████████████████████████████████████████████████████|2/2
!!! ERROR 'search_query' is in an unescaped block ('autoescape false') and is XSSable in ./xss-demo/templates/index.html
```

## Tests

The tests will run this experiment on some open source flask repos with known reflected XSS vulnerabilities.

```
$ pipenv shell
$ pipenv install --dev
$ export PYTHONPATH=.
$ pytest
```
