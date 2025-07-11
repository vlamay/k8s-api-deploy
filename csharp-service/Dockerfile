# Stage 1: Build
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /app

# Copy csproj and restore as distinct layers
COPY CSharpService/CSharpService.csproj ./CSharpService/
RUN dotnet restore CSharpService/CSharpService.csproj

# Copy everything else and build
COPY CSharpService/. ./CSharpService/
WORKDIR /app/CSharpService
RUN dotnet publish -c Release -o /app/publish --no-restore

# Stage 2: Runtime
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish .

EXPOSE 8080
# For ASP.NET Core, Kestrel listens on port 8080 by default for HTTP when running in a container.
# If not, we might need: ENV ASPNETCORE_URLS=http://+:8080
ENTRYPOINT ["dotnet", "CSharpService.dll"]
