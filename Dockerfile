FROM ubuntu:latest AS build
LABEL authors="clemens"

RUN apt-get update && \
    apt-get install -y git cmake build-essential && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .

RUN mkdir "build" && cd "build" && cmake -DCMAKE_EXE_LINKER_FLAGS="-static" -DCMAKE_BUILD_TYPE=Release .. && make

FROM ubuntu:latest AS deploy
COPY --from=build /build/build/etherbridge /
ENTRYPOINT ["/etherbridge"]