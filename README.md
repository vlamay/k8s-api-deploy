# Cross-Language CI/CD Pipeline for Microservices

This project demonstrates a microservices application built with four different programming languages: C++, C#, Java, and Python. Each service runs in its own Docker container and exposes specific endpoints. The project includes a CI/CD pipeline using GitHub Actions for building, testing, and (optionally) deploying these services.

## Architecture

The application consists of four independent microservices:

*   **C++ Service (`cpp-service`):** A lightweight HTTP server using `cpp-httplib`.
*   **C# Service (`csharp-service`):** An ASP.NET Core Web API.
*   **Java Service (`java-service`):** A Spring Boot application.
*   **Python Service (`python-service`):** A Flask application.

Each service is containerized using Docker and can be run locally via `docker-compose`. The CI/CD pipeline in GitHub Actions automates the build and basic testing of each service.

## Prerequisites

*   **Docker:** Required for building and running the services. Install Docker Desktop or Docker Engine.
*   **Git:** For cloning the repository.
*   **(Optional) .NET SDK 8:** If you want to build/run the C# service locally without Docker.
*   **(Optional) JDK 17+ & Gradle:** If you want to build/run the Java service locally without Docker.
*   **(Optional) Python 3.9+:** If you want to build/run the Python service locally without Docker.
*   **(Optional) C++ Compiler (g++) & OpenSSL libs:** If you want to build/run the C++ service locally without Docker.

## Getting Started

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd <repository-name>
    ```

2.  **Run all services using Docker Compose:**
    This is the recommended way to run all services together locally.
    ```bash
    docker-compose up --build
    ```
    This command will build the Docker images for each service (if not already built) and start them. Services will be accessible on the host machine at the ports specified below.

## Services and Endpoints

The following table details each microservice, its exposed port on the host (when run via `docker-compose`), and example `curl` commands to test its endpoints:

| Service          | Directory        | Host Port | Container Port | Endpoint         | Method | `curl` Example (run from your host terminal)                                                                 | Expected Response (example)                                                                 |
| ---------------- | ---------------- | --------- | -------------- | ---------------- | ------ | ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------- |
| **C++ Service**  | `cpp-service`    | `8081`    | `8080`         | `/status`        | GET    | `curl http://localhost:8081/status`                                                                          | `{"status": "OK", "service": "C++"}`                                                        |
| **C# Service**   | `csharp-service` | `8082`    | `8080`         | `/version`       | GET    | `curl http://localhost:8082/version`                                                                         | `{"service":"C#","version":"1.0.0","dotnetVersion":"8.x.x"}` (dotnetVersion will vary)      |
| **Java Service** | `java-service`   | `8083`    | `8080`         | `/echo`          | POST   | `curl -X POST -H "Content-Type: application/json" -d '{"name":"test"}' http://localhost:8083/echo`         | `{"service":"Java","receivedPayload":{"name":"test"},"message":"Echo successful"}`         |
|                  |                  |           |                | `/metrics`       | GET    | `curl http://localhost:8083/metrics`                                                                         | `{"service_name":"JavaService","requests_processed_count":1}` (count will increment)        |
| **Python Service**| `python-service` | `8084`    | `5000`         | `/health`        | GET    | `curl http://localhost:8084/health`                                                                          | `{"service":"Python","status":"UP"}`                                                        |
|                  |                  |           |                | `/metrics`       | GET    | `curl http://localhost:8084/metrics`                                                                         | `{"errors_encountered":0,"requests_processed":123,"service_name":"PythonService","uptime_seconds":...}` |

## Building Individual Services

You can build the Docker image for each service individually. Navigate to the service's directory and run:

*   **C++ Service:**
    ```bash
    cd cpp-service
    docker build -t cpp-service:latest .
    cd ..
    ```
*   **C# Service:**
    ```bash
    cd csharp-service
    docker build -t csharp-service:latest .
    # Note: The Dockerfile is in csharp-service/, project is in csharp-service/CSharpService/
    cd ..
    ```
*   **Java Service:**
    ```bash
    cd java-service
    docker build -t java-service:latest .
    cd ..
    ```
*   **Python Service:**
    ```bash
    cd python-service
    docker build -t python-service:latest .
    cd ..
    ```

## CI/CD Pipeline (GitHub Actions)

The project includes a CI/CD pipeline defined in `.github/workflows/ci.yml`. This pipeline automates the following for each microservice:

1.  **Trigger:** Runs on pushes and pull requests to the `main` branch.
2.  **Matrix Build:** Uses a matrix strategy to process each service (`cpp-service`, `csharp-service`, `java-service`, `python-service`) in parallel jobs.
3.  **Checkout Code:** Checks out the latest version of the repository.
4.  **Set up Docker Buildx:** Initializes Docker Buildx for efficient image building.
5.  **Build Docker Image:** Builds the Docker image for the specific service in the matrix. For example, for `cpp-service`, it runs `docker build -t cpp-service:latest ./cpp-service`.
6.  **Basic Test:**
    *   Runs the newly built Docker container in detached mode, mapping its port to a host port.
    *   Waits for a few seconds for the service to initialize.
    *   Performs a `curl` request to a key endpoint of the service:
        *   C++: `GET /status`
        *   C#: `GET /version`
        *   Java: `POST /echo` (with sample JSON data)
        *   Python: `GET /health`
    *   Checks the `curl` command's exit status to determine if the basic test passed.
    *   Stops and removes the test container.
7.  **(Future Enhancement) Push Docker Image:** The workflow includes commented-out steps for logging into a container registry (like Docker Hub or GHCR) and pushing the built images. This is typically done only on pushes to the `main` branch.

This CI setup ensures that each service can be independently built and passes a basic runtime health check, providing quick feedback on code changes.

## Future Enhancements (Examples from Discussion)

*   **Advanced Testing:** Integrate unit test execution (CTest, `dotnet test`, JUnit, `pytest`) directly into the CI pipeline for each service.
*   **Linting & Static Analysis:** Add linters (e.g., `clang-tidy`, `flake8`) and static analysis tools.
*   **DevSecOps:** Incorporate security scanning tools like Trivy (for Docker images and dependencies) and Semgrep/Bandit (for code).
*   **Container Registry:** Fully implement pushing images to GitHub Container Registry (ghcr.io) or Docker Hub.
*   **Deployment:** Add deployment steps (e.g., to Kubernetes using Helm/ArgoCD, or updating a `docker-compose` setup on a server).
*   **Monitoring:** Integrate Prometheus for metrics collection and Grafana for dashboards.
*   **Logging:** Implement centralized logging with Loki and Promtail.
*   **API Gateway:** Introduce an NGINX or Traefik reverse proxy.
*   **Makefile/Scripts:** Add a `Makefile` or shell scripts for easier local development workflows.

This README provides a comprehensive overview of the project in its current state.
