# Stage 1: Build the C++ application
FROM gcc:latest AS builder

WORKDIR /app

# Install OpenSSL development libraries
RUN apt-get update && apt-get install -y libssl-dev

COPY httplib.h .
COPY main.cpp .

# Compile the C++ application
# -I. to find httplib.h in the current directory
# -lssl -lcrypto for OpenSSL
# -lpthread for pthread
RUN g++ main.cpp -o cpp_service -I. -std=c++17 -lpthread -lssl -lcrypto -static-libstdc++ -static-libgcc

# Stage 2: Create the runtime image
FROM debian:buster-slim
# FROM scratch # For a truly minimal image, but requires a static binary and careful handling of certs

WORKDIR /app

# Install runtime dependencies for OpenSSL and CA certificates
RUN apt-get update && \
    apt-get install -y libssl1.1 ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy the compiled application from the builder stage
COPY --from=builder /app/cpp_service .

EXPOSE 8080

# Run the C++ service
CMD ["./cpp_service"]
