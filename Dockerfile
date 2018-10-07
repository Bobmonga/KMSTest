FROM microsoft/aspnetcore-build AS build-env
RUN dir
COPY src /app
WORKDIR /app

RUN dotnet restore 
#--configfile ../NuGet.Config
RUN dotnet publish -c Release -o out

# Build runtime image
FROM microsoft/aspnetcore
WORKDIR /app
COPY --from=build-env /app/KMSTest/out .
ENV ASPNETCORE_URLS http://*:5000
ENTRYPOINT ["dotnet", "KMSTest.dll"]