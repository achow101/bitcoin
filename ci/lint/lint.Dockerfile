FROM ubuntu:jammy
ARG python_version

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y \
    build-essential \
    clang \
    curl \
    gawk \
    git \
    jq \
    libbz2-dev \
    libffi-dev \
    liblzma-dev \
    libncursesw5-dev \
    libreadline-dev \
    libsqlite3-dev \
    libssl-dev \
    libxml2-dev \
    libxmlsec1-dev \
    llvm \
    tk-dev \
    xz-utils \
    zlib1g-dev 

RUN git clone https://github.com/pyenv/pyenv.git
ENV PYENV_ROOT /pyenv
ENV PATH $PYENV_ROOT/shims:$PYENV_ROOT/bin:$PATH
RUN pyenv rehash
RUN cd $PYENV_ROOT && git pull
env PYENV_VERSION $python_version
RUN env CC=clang CXX=clang++ pyenv install $python_version

RUN pip install codespell==2.2.1 flake8==5.0.4 mypy==0.971 pyzmq==24.0.1 vulture==2.6

ENV SHELLCHECK_VERSION=v0.8.0
RUN curl -sL "https://github.com/koalaman/shellcheck/releases/download/${SHELLCHECK_VERSION}/shellcheck-${SHELLCHECK_VERSION}.linux.x86_64.tar.xz" | tar --xz -xf - --directory /tmp/
ENV PATH "/tmp/shellcheck-${SHELLCHECK_VERSION}:${PATH}"
