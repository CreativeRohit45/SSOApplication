# ----- Stage 1: Build -----
# Use a base image with Java 17 JDK (matching your pom.xml)
FROM eclipse-temurin:17-jdk-jammy AS builder

# Set the working directory inside the image
WORKDIR /app

# --- THIS IS THE FIX ---
# Copy everything from the repository root (where pom.xml is)
# into the /app directory in the image.
COPY . .

# Grant execute permission to the maven wrapper
RUN chmod +x ./mvnw

# Build the application, skipping tests
# This will create the .jar file in /app/target/
RUN ./mvnw clean package -DskipTests

# ----- Stage 2: Run -----
# Use a minimal JRE-only image for a smaller final size
FROM eclipse-temurin:17-jre-jammy

# Set the working directory
WORKDIR /app

# Copy ONLY the built .jar file from the 'builder' stage
# The jar name 'demo-0.0.1-SNAPSHOT.jar' comes from your pom.xml
COPY --from=builder /app/target/demo-0.0.1-SNAPSHOT.jar app.jar

# Expose the port your Spring Boot app runs on (default 8080)
EXPOSE 8080

# The command to run your application
ENTRYPOINT ["java", "-jar", "app.jar"]