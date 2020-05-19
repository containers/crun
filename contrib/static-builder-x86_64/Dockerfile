FROM nixos/nix
COPY . /crun
WORKDIR crun/nix
RUN nix-build
WORKDIR /
RUN rm -rf crun
