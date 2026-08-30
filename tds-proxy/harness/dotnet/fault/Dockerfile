# #40 dotnet fault harness: Microsoft.Data.SqlClient (.NET 8), pre-built Fault.dll. Throwaway; never a real DB.
FROM mcr.microsoft.com/dotnet/sdk:8.0
WORKDIR /app
COPY Fault.csproj .
RUN dotnet restore
COPY Program.cs .
RUN dotnet build -c Release -o /out
ENTRYPOINT ["dotnet","/out/Fault.dll"]
