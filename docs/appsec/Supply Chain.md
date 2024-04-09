# Supply Chain
## Supply Chain Attacks
### GitHub repo-jacking
From: [How to stay safe from repo-jacking - The GitHub Blog](https://github.blog/2024-02-21-how-to-stay-safe-from-repo-jacking/)
#### Concept
GitHub were to change its account name to `gh`[1](https://github.blog/2024-02-21-how-to-stay-safe-from-repo-jacking/?utm_source=tldrsec.com&utm_medium=referral&utm_campaign=tl-dr-sec-223-ai-auto-fixes-mapping-cloudtrail-to-incidents-vs-code-extensions-for-security#fn-76655-1 "Read footnote."). Then, a repository such as [https://github.com/github/cmark-gfm](https://github.com/github/cmark-gfm) would be renamed to [https://github.com/gh/cmark-gfm](https://github.com/github/cmark-gfm). Now, imagine that an attacker manages to register a new GitHub account with the newly available username `github`. Then, they could create a repository named `cmark-gfm` and start serving malware to developers who are still downloading their software from the original address.
#### Targets
1. You’re using [GitHub Actions](https://docs.github.com/actions).
2. You’re using the [Go programming language](https://go.dev/).
3. You’re using [git submodules](https://git-scm.com/docs/git-submodule).

