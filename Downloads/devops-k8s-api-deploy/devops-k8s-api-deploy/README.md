# DevOps: Auto Deploy API to Kubernetes 🚀

This project demonstrates a CI/CD pipeline for deploying a containerized FastAPI app to Kubernetes using GitHub Actions and Docker.

## 🔧 Stack
- Python (FastAPI)
- Docker
- GitHub Actions
- Kubernetes (Minikube)

## 🚀 Pipeline Flow
1. Push to `main` → 
2. Build & push Docker image →
3. Deploy to Kubernetes cluster

## 🧪 Run Locally
```bash
minikube start
kubectl apply -f k8s/
minikube service api-service
```
