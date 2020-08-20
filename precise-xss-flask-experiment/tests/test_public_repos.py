import pytest
import subprocess
import os

@pytest.fixture(
    scope="module",
    params=[
        ("https://github.com/minusworld/xss-demo" , "6f3d51898c36fd7bbe38de8400765bc0f3d5d2a6"),
        ("https://github.com/ucfopen/lti-template-flask" , "6223a4683dfa12ab3891476b503d419107543065"),
        ("https://github.com/terrabitz/Flask_XSS" , "4d6f500246696d9078e141d7eabcc34087c54faa"),
    ]
)
def checkout_repo(request, tmp_path_factory):
    repo_url = request.param[0]
    commit_hash = request.param[1]

    temp_dir = tmp_path_factory.mktemp("repos")

    name = repo_url.split("/")[-1]
    target_dir = os.path.join(temp_dir, name)

    subprocess.run(
        ["git", "clone", repo_url, target_dir]
    )

    if commit_hash:
        subprocess.run(
            ["git", "checkout", commit_hash],
            cwd=target_dir
        )

    subprocess.run(
        ["git", "clean", "-xdf"],
        cwd=target_dir
    )

    return target_dir


def test_xss_match_on_public_repos(checkout_repo):
    from xss_match import try_xss_match
    findings = try_xss_match.main(checkout_repo)
    for finding in findings:
        print(finding)
    assert len(findings) > 0
