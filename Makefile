.PHONY: start stop status delete build run

build:
	minikube image build -t blobstore:latest -f ./src/Dockerfile ./src

start:
	minikube start
	$(MAKE) build
	kubectl apply -f k8s/redis-pvc.yaml
	kubectl apply -f k8s/redis.yaml
	kubectl apply -f k8s/minio-pvc.yaml
	kubectl apply -f k8s/minio.yaml
	kubectl apply -f k8s/prometheus.yaml
	kubectl apply -f k8s/grafana.yaml
	kubectl apply -f k8s/blobstore.yaml

stop:
	minikube stop

status:
	minikube status

delete:
	minikube delete

run:
	cat USAGE.md
	minikube tunnel
