# Stage 1: Build the application
FROM maven:3.9-eclipse-temurin-21 AS builder
WORKDIR /app

# Copy the pom.xml and download dependencies
# This step is cached unless pom.xml changes
COPY pom.xml .
RUN mvn dependency:go-offline

# Copy the source code and build the application
COPY src ./src
RUN mvn clean package -DskipTests

# Stage 2: Create the minimal runtime image
FROM eclipse-temurin:21-jre
WORKDIR /app

# Define an environment variable for the upload directory
ENV UPLOAD_DIR=/app/uploads

# Create the upload directory and the user, then set permissions
RUN mkdir -p /app/uploads && \
    useradd -m -s /bin/bash abeuser && \
    chown -R abeuser:abeuser /app

# Copy the built jar file from the builder stage
COPY --from=builder /app/target/*.jar app.jar

# Switch to the secure user
USER abeuser

# Expose the application port
EXPOSE 8080

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]
