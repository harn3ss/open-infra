# Microsoft.Data.SqlClient (.NET 8) for the #3 driver-coverage grid. Built + run against the throwaway
# backend, then the image is removed — never point it at a real database.
FROM mcr.microsoft.com/dotnet/sdk:8.0
WORKDIR /app
COPY Run.csproj .
RUN dotnet restore
COPY Program.cs .
RUN dotnet build -c Release -o /out
ENTRYPOINT ["dotnet", "/out/Run.dll"]
