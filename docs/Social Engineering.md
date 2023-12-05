# Social Engineering
## Ideas
- https://www.reddit.com/r/cybersecurity/comments/16z2wvf/cell_carriers_and_dmarcspf/
- https://www.reddit.com/r/freedommobile/comments/ytgebe/email_to_text_possible_still/
- https://www.reddit.com/r/cybersecurity/comments/16zl6ue/it_time_we_talked_about_cloudflare/
- [(10) Spoofing ID-Call : redteamsec (reddit.com)](https://www.reddit.com/r/redteamsec/comments/173058q/spoofing_idcall/)
- [Abusing Microsoft Access "Linked Table" Feature to Perform NTLM Forced Authentication Attacks - Check Point Research](https://research.checkpoint.com/2023/abusing-microsoft-access-linked-table-feature-to-perform-ntlm-forced-authentication-attacks/)

## Clone A Website
### Wayback Machine  (*Recommended*)
- Install `rubygems` using `sudo apt-get install rubygems`
- Install and use[GitHub - hartator/wayback-machine-downloader: Download an entire website from the Wayback Machine.](https://github.com/hartator/wayback-machine-downloader#installation)
### Wget
```bash
# Download website using wget
wget --mirror --convert-links --adjust-extension --page-requisites --no-parent https://www.sabic.com/ar --level=1 --user-agent=Mozilla  –-max-redirect=0 --accept-regex ".*[.].*"
```
## MiTM
- [fkasler/cuddlephish: Weaponized Browser-in-the-Middle (BitM) for Penetration Testers (github.com)](https://github.com/fkasler/cuddlephish)
- [Browser In The Browser (BITB) Templates](https://github.com/mrd0x/BITB)

References:
- [How To Download A Website With Wget The Right Way | Simple IT 🤘 Rocks](https://simpleit.rocks/linux/how-to-download-a-website-with-wget-the-right-way/)
- [Recursive Accept/Reject Options (GNU Wget 1.21.1-dirty Manual)](https://www.gnu.org/software/wget/manual/html_node/Recursive-Accept_002fReject-Options.html)


