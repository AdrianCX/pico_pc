FROM ubuntu:20.04

RUN apt-get update && apt-get install -y cmake g++

WORKDIR /source/
COPY . /source/
RUN mkdir docker_build && cd docker_build && cmake -DCMAKE_BUILD_TYPE=Release .. && make

FROM ubuntu:20.04

WORKDIR /runtime/
COPY --from=0 /source/docker_build/pico_hole/pico_hole .

CMD ["/runtime/pico_hole"]