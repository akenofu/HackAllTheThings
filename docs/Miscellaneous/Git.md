# Git
## Use Primary Access Token (PAT) to clone repo
```bash
git clone https://kogytytnmvmj33k6urfadfxj3cou6fwmain26v5jwxamttf3tlkqq@dev.azure.com /DevOps/Terraform/_git/Terraform
```

## Git meta data about repo from GitHub API
```http
https://api.github.com/repos/molenzwiebel/Deceive/releases/latest
``` 

![](/Screenshots/Pasted%20image%2020230104034321.png)

## Dump git repo from website
[arthaud/git-dumper: A tool to dump a git repository from a website (github.com)](https://github.com/arthaud/git-dumper)
> Use grep to identify non-patched dependencies

or
```bash
# Download repo exposed from webserver
wget -r https://0acf008f04cdf285c14b7b1c0012006e.web-security-academy.net/.git/
```

## Diff-ing git commits
```bash
# List commits
git log

# Show changes in commit
git log -p <commit_id>
```