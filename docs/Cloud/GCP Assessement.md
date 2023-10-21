# GCP Assessement
## Automated
- [carlospolop/PurplePanda: Identify privilege escalation paths within and across different clouds (github.com)](https://github.com/carlospolop/PurplePanda)
## CLI
```bash
# Get current logged in account
gcloud config get-value account

# List roles and bindings — project level
gcloud projects get-iam-policy <project>

# Get role for compute instance
gcloud projects get-iam-policy <compute_instance_name>

# Describe Role in terms of granular permissions
gcloud iam roles describe <role> --project <project> 

# Scoutesuite
python3 scout.py gcp --user-account | tee <client>.scoutsuite
```

## Priv Esc Learning Resources
- [Tutorial on privilege escalation and post exploitation tactics in Google Cloud Platform environments | GitLab](https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform/)
- [Google Cloud Platform (GCP) Service Account-based Privilege Escalation paths - Praetorian](https://www.praetorian.com/blog/google-cloud-platform-gcp-service-account-based-privilege-escalation-paths/)
- [Lateral Movement & Privilege Escalation in GCP; Compromise Organizations without Dropping an Implant - YouTube](https://www.youtube.com/watch?v=kyqeBGNSEIc)
- [RhinoSecurityLabs/GCP-IAM-Privilege-Escalation: A collection of GCP IAM privilege escalation methods documented by the Rhino Security Labs team. (github.com)](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation)
- [GCP Pentesting - HackTricks Cloud](https://cloud.hacktricks.xyz/pentesting-cloud/gcp-pentesting)

## Hardening Resources
[GCP Best practices | GitLab](https://about.gitlab.com/handbook/security/planning/security-development-deployment-requirements/)