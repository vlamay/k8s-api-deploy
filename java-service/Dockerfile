# Stage 1: Build the application
FROM gradle:8.5-jdk17-alpine AS builder
# FROM eclipse-temurin:17-jdk-jammy AS builder
WORKDIR /app

# Copy gradle files
COPY build.gradle .
# COPY settings.gradle . # If you have one
# COPY gradlew .
# COPY gradle ./gradle

# Copy source code
COPY src ./src

# Grant execute permission for gradlew if it were used (not using it directly here for simplicity)
# RUN chmod +x ./gradlew

# Build the application
RUN gradle build --no-daemon

# Stage 2: Create the runtime image
FROM eclipse-temurin:17-jre-jammy
WORKDIR /app

# Copy the JAR file from the builder stage
# The JAR file is typically found in build/libs/
# The name might vary, so using a wildcard and then renaming or relying on a fixed name.
# Assuming the jar is named based on project and version, like javaservice-0.0.1-SNAPSHOT.jar
# For simplicity, let's assume it's the only jar or the one we need.
COPY --from=builder /app/build/libs/*.jar app.jar

EXPOSE 8080

# Run the Java application
ENTRYPOINT ["java", "-jar", "app.jar"]
