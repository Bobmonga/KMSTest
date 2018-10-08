FROM microsoft/dotnet:2.1-sdk AS build-env
RUN dotnet --info
COPY src /app
WORKDIR /app

RUN dotnet restore 
#--configfile ../NuGet.Config
RUN dotnet publish -c Release -o out

# Build runtime image
FROM microsoft/dotnet:2.1-runtime
WORKDIR /app
COPY --from=build-env /app/KMSTest/out .
ENV ASPNETCORE_URLS http://*:5000
ENTRYPOINT ["dotnet", "KMSTest.dll"]