# Usage

Get the external IP:
```
kubectl get svc blobstore
```

## Examples

```
curl http://<EXTERNAL-IP>:8080/fortune

curl -X POST http://<EXTERNAL-IP>:8080/login

curl http://<EXTERNAL-IP>:8080/get?key=mykey

curl -X POST -d 'value=myvalue' http://<EXTERNAL-IP>:8080/put?key=mykey

curl -X DELETE http://<EXTERNAL-IP>:8080/delete?key=mykey
```

## MinIO Console

```
kubectl port-forward svc/minio 9001:9001
```

Open http://localhost:9001 and login with `minioadmin` / `minioadmin`.

S3 API available at `minio:9000` within the cluster.
