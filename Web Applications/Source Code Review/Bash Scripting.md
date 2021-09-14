## Grep cheatsheet
```bash
# with colors and recursive
grep -r "function AddAttachment" --color 2>/dev/null /usr/local/atmail/
```

## Examine File structure
```bash
tree -L 3 .
```

## Unzip Ear Files
```bash
unzip -q  application.ear -d application
```

## Get MiliSeconds since EPOCH
```bash
# includes 3 digits of miliseconds
date +%s%3N
```