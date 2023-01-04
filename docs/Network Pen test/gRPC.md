# gRPC
## Identify gRPC services via reflection
> Another way is described in this [write up](https://github.com/righettod/toolbox-pentest-web/blob/master/docs/BroBox_write_up.pdf) if reflection is not enabled.

The tool `grpcurl` will be used for this operation.

```bash
# List available services exposed on host "fc.xlm-box.com:443"
$ grpcurl fc.xlm-box.com:443 list
grpc.reflection.v1alpha.ServerReflection
identity.Auth

# List available methods for the service named "identity.Auth" 
$ grpcurl fc.xlm-box.com:443 list identity.Auth
identity.Auth.GetSalt
identity.Auth.GetUser
identity.Auth.GetUsers

# Get the signature of the method named "identity.Auth.GetUsers"
$ grpcurl fc.xlm-box.com:443 describe identity.Auth.GetUsers
identity.Auth.GetUsers is a method:
rpc GetUsers ( .identity.UsersRequest ) returns ( stream .identity.UserReply );

# Get the structure of the parameter named ".identity.UsersRequest"
$ grpcurl fc.xlm-box.com:443 describe .identity.UsersRequest
identity.UsersRequest is a message:
message UsersRequest {
  int32 limit = 1;
}
```

## MITM
[bradleyjkemp/grpc-tools: A suite of gRPC debugging tools. Like Fiddler/Charles but for gRPC. (github.com)](https://github.com/bradleyjkemp/grpc-tools)

## References
[toolbox-pentest-web/README.md at master · righettod/toolbox-pentest-web (github.com)](https://github.com/righettod/toolbox-pentest-web/blob/master/docs/README.md#identify-grpc-services-via-reflection)
[Pentesting gRPC / Protobuf : Decoding First steps – David Vassallo's Blog](https://blog.davidvassallo.me/2018/10/17/pentesting-grpc-protobuf-decoding-first-steps/)

## Tools
[bradleyjkemp/grpc-tools: A suite of gRPC debugging tools. Like Fiddler/Charles but for gRPC. (github.com)](https://github.com/bradleyjkemp/grpc-tools)
[fullstorydev/grpcurl: Like cURL, but for gRPC: Command-line tool for interacting with gRPC servers (github.com)](https://github.com/fullstorydev/grpcurl)