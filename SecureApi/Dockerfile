# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy only the project file first (better caching)
COPY SecureApi/SecureApi.csproj SecureApi/
RUN dotnet restore SecureApi/SecureApi.csproj

# Copy the rest of the source
COPY . .

# Build and publish
RUN dotnet publish SecureApi/SecureApi.csproj -c Release -o /app/out

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app/out .

ENV ASPNETCORE_URLS=http://0.0.0.0:10000
EXPOSE 10000

ENTRYPOINT ["dotnet", "SecureApi.dll"]