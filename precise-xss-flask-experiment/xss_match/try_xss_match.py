import logging
import sys
import subprocess
import json
import re
import os

logger = logging.getLogger(__file__)
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(stream=sys.stderr)
handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)

def gather_all_templates(app_root="."):
    for root, _, filenames in os.walk(app_root):
        if "templates" in root:
            for filename in filenames:
                yield os.path.join(root, filename)

def main(app_root):
    results_raw = subprocess.check_output([
        "which",
        "semgrep"
    ])

    logger.debug(f"semgrep location: {results_raw.decode('utf-8')}")

    results_raw = subprocess.check_output([
        "semgrep",
        "--json",
        "-f",
        "rules/gather-template-context-user-input.yaml",
        app_root,
    ])

    template_context_vars = json.loads(results_raw)
    template_context_var_names = set([result.get('extra', {}).get('message') for result in template_context_vars.get('results', [])]) 

    results_raw = subprocess.check_output([
        "semgrep",
        "--json",
        "-f",
        "rules/gather-unescaped-user-input.yaml",
        app_root,
    ])

    unescaped_user_input = json.loads(results_raw)
    potentially_unescaped_user_input = set([result.get('extra', {}).get('message') for result in unescaped_user_input.get('results', [])])

    template_paths = list(gather_all_templates(app_root))

    output = []

    # For autoescaping behavior:
    # https://flask.palletsprojects.com/en/1.1.x/templating/#controlling-autoescaping
    # - In the Python code, wrap the HTML string in a Markup object before passing it to the template. This is in general the recommended way.
    # - Inside the template, use the |safe filter to explicitly mark a string as safe HTML ({{ myvariable|safe }})
    # - Temporarily disable the autoescape system altogether.
    for template_path in template_paths:
        logger.debug(f"reading template {template_path}...")
        with open(template_path, 'r') as fin:
            fcontents = fin.read()

        # 1. var is user input
        # 2. var is explicitly unescaped in code w/ Markup (or unescaped extension)
        # 3. var is anywhere in template
        template_vars = set([match.group(1) for match in re.finditer("{{\s*(.*?)\s*}}", fcontents)])
        definitely_xss = potentially_unescaped_user_input.intersection(template_vars)

        for var in definitely_xss:
            output.append(f"!!! ERROR '{var}' is not escaped in Python code and is XSSable in {template_path}")

        # 1. var is user input
        # 2. var is in unescaped context
        unescaped_contexts = list(re.finditer("{% autoescape false %}(.*){% endautoescape %}", fcontents.replace('\n', '')))
        for context in unescaped_contexts:
            unescaped_context_template_vars = set([match.group(1) for match in re.finditer("{{\s*(.*?)\s*}}", context.group(1))])
            definitely_xss = template_context_var_names.intersection(unescaped_context_template_vars)
            for var in definitely_xss:
                output.append(f"!!! ERROR '{var}' is in an unescaped block ('autoescape false') and is XSSable in {template_path}")

        # 1. var is user input
        # 2. var is explicitly unescaped in template with '| safe'
        for tvar in template_vars:
            explicitly_escaped_vars = set([match.group(1).strip() for match in re.finditer("(.*?)\|\s*safe", tvar)])
            definitely_xss = explicitly_escaped_vars.intersection(template_context_var_names)
            for var in definitely_xss:
                output.append(f"!!! ERROR '{var}' is explicitly unescaped with '| safe' and is XSSable in {template_path}")

    return output

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("app_root")
    parser.add_argument("--json", action="store_true")

    args = parser.parse_args()

    findings = main(args.app_root)
    if args.json:
        results = {
            'results': [{
                'id': 'xss',
                'path': finding.split(' ')[-1],
                'message': finding,
            } for finding in findings]
        }
        print(json.dumps(results))
    else:
        for finding in findings:
            print(finding)
