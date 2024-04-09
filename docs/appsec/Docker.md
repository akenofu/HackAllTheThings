# Docker
## Docker Concepts
- [Dockerfile ENTRYPOINT: Everything You Need To Know (kinsta.com)](https://kinsta.com/blog/dockerfile-entrypoint/)
- [Docker image vs container: What are the differences? | CircleCI](https://circleci.com/blog/docker-image-vs-container/#:~:text=An%20image%20is%20a%20snapshot,efficiently%20from%20producer%20to%20consumer.)
- [Running a Docker container as a non-root user | by Lucas Wilson-Richter | Redbubble | Medium](https://medium.com/redbubble/running-a-docker-container-as-a-non-root-user-7d2e00f8ee15)
- [Docker ENTRYPOINT and CMD : Differences & Examples (spacelift.io)](https://spacelift.io/blog/docker-entrypoint-vs-cmd)
- [dockerfile - denied: requested access to the resource is denied: docker - Stack Overflow](https://stackoverflow.com/questions/41984399/denied-requested-access-to-the-resource-is-denied-docker)
- [Static vulnerability scanning | Docker Docs](https://docs.docker.com/docker-hub/vulnerability-scanning/#:~:text=This%20page%20describes%20the%20legacy%20static%20vulnerability%20scanning,requires%20a%20Docker%20Pro%2C%20Team%2C%20or%20Business%20subscription.)
- [Docker Scout | Docker Docs](https://docs.docker.com/scout/)
- [Set up Automated Builds | Docker Docs](https://docs.docker.com/docker-hub/builds/)
## Docker Fundamentals
- [Lesson 1: Understand Docker from a security perspective - Practical DevSecOps (practical-devsecops.com)](https://www.practical-devsecops.com/lesson-1-understand-docker-from-a-security-perspective/)
- [Lesson 2: Docker Images, Docker Layers, and Registry - Practical DevSecOps (practical-devsecops.com)](https://www.practical-devsecops.com/lesson-2-docker-images-docker-layers-and-registry/)
- [Lesson #3: Container reconnaissance techniques for beginners - Practical DevSecOps (practical-devsecops.com)](https://www.practical-devsecops.com/lesson-3-container-reconnaissance-techniques-for-beginners/)
## Docker Hacking
- [Lesson 4: Hacking Containers Like A Boss - Practical DevSecOps (practical-devsecops.com)](https://www.practical-devsecops.com/lesson-4-hacking-containers-like-a-boss/)
- [Lesson 5: Hacking Containers Like A Boss - Part 2 - Practical DevSecOps (practical-devsecops.com)](https://www.practical-devsecops.com/lesson-5-hacking-containers-like-a-boss-part-2/)

## Docker Hardening
- [Lesson 6: Defending container Infrastructure - Practical DevSecOps (practical-devsecops.com)](https://www.practical-devsecops.com/lesson-6-defending-container-infrastructure/)


## Build Image locally
```bash
# Build the image
docker build -t <image_name>:<tag> .

# Build image from file path
docker build -t <image_name>:<tag> -f .\docker\Dockerfile .
```

## Run images in a docker network
```bash
# Create docker network
docker network create -d bridge my-nat

# Run the image in a custom NAT with port mapping and volume mapping
docker run --name=server -p 80:8000 -v $(pwd):/app --network=my-nat -itd  build

# Get a shell on container
docker run -it --network=my-nat test /bin/bash
```
## Push image to Docker Registry
```bash
# Generate your PAT from https://hub.docker.com/settings/security
docker login -u <username>

# tag image to dockerhub
# docker tag mylocalimage:latest darlin/dockerhub:myfirstimagepush
docker tag sslyze:1.0 akenofu/sslyze:1.0

# Push image
            # user/image:tag
docker push akenofu/sslyze:1.0
```

## Fix Docker Security issues
Once a list of vulnerabilities have been identified, there are a couple of actions you can take to remediate the vulnerabilities. For example, you can:

1. Specify an updated base image in the Dockerfile, check your application-level dependencies, rebuild the Docker image, and then push the new image to Docker Hub.
2. Rebuild the Docker image, run an update command on the OS packages, and push a newer version of image to Docker Hub.
3. Edit the Dockerfile to manually remove or update specific libraries that contain vulnerabilities, rebuild the image, and push the new image to Docker Hub

Docker Scout can provide you with concrete and contextual remediation steps for improving image security. For more information, see [Docker Scout](https://docs.docker.com/scout/).
```
# Display Recommendations
docker scout recommendations

# Find only high issues in a nice format
docker scout cves --only-severity high --format only-packages --only-vuln-packages akenofu/sslyze:1.0
```
CI/CD Integration available at: [GitHub - docker/scout-cli: Docker Scout CLI](https://github.com/docker/scout-cli)