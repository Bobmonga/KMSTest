FROM microsoft/microsoft/dotnet-framework-build AS build-env
RUN dotnet --info
COPY src /app
WORKDIR /app

RUN dotnet restore 
#--configfile ../NuGet.Config
RUN dotnet publish -c Release -o out

# Build runtime image
FROM microsoft/dotnet
WORKDIR /app
COPY --from=build-env /app/KMSTest/out .
ENV ASPNETCORE_URLS http://*:5000
ENTRYPOINT ["dotnet", "KMSTest.dll"]