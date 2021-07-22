FROM ubuntu:16.04

WORKDIR /fuzz

RUN apt-get update -y
RUN apt-get install --yes apt-utils
RUN apt-get install sudo
RUN apt-get --yes install git
RUN git clone https://github.com/google/fuzzing.git fuzzing
RUN git clone https://github.com/google/fuzzer-test-suite.git FTS
RUN sudo apt-get update
RUN sudo apt-get --yes install curl subversion screen gcc g++ cmake ninja-build golang autoconf libtool apache2 python-dev pkg-config zlib1g-dev libgcrypt-dev libgss-dev libssl-dev libxml2-dev ragel nasm libarchive-dev make automake libdbus-1-dev libboost-dev autoconf-archive tar libncurses5-dev libncursesw5-dev
RUN ./fuzzing/tutorial/libFuzzer/install-clang.sh

CMD ["bash"]