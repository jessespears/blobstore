# Usage

Get the external IP:
```
kubectl get svc blobstore
```

## Examples

```
curl http://<EXTERNAL-IP>:8080/fortune

curl -X POST -d 'username=alice&password=secret' http://<EXTERNAL-IP>:8080/register

curl -c cookies.txt -X POST -d 'username=alice&password=secret' http://<EXTERNAL-IP>:8080/login

curl -b cookies.txt -X POST -d 'value=s3://bucket/obj' http://<EXTERNAL-IP>:8080/put?key=mykey

curl -b cookies.txt http://<EXTERNAL-IP>:8080/get?key=mykey

curl -b cookies.txt -X DELETE http://<EXTERNAL-IP>:8080/delete?key=mykey
```

## MinIO Console

```
kubectl port-forward svc/minio 9001:9001
```

Open http://localhost:9001 and login with `minioadmin` / `minioadmin`.

S3 API available at `minio:9000` within the cluster.
