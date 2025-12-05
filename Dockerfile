FROM --platform=linux/amd64 haskell:9.12

RUN apt-get update && apt-get install -y \
    python3 \
    build-essential \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*


WORKDIR /tmp/mctiny
COPY mctiny /tmp/mctiny


RUN make clean && make


RUN cp libmctiny.so /usr/local/lib/

RUN cp mctiny.h /usr/local/include/ && \
    cp crypto_kem_mceliece6960119.h /usr/local/include/

RUN cp mctiny-test /usr/local/bin/

RUN ldconfig

WORKDIR /app


ENV LD_LIBRARY_PATH="/usr/local/lib:$LD_LIBRARY_PATH" \
    LIBRARY_PATH="/usr/local/lib:$LIBRARY_PATH" \
    C_INCLUDE_PATH="/usr/local/include:$C_INCLUDE_PATH"

RUN echo "package *" > cabal.project.local && \
    echo "  extra-include-dirs: /usr/local/include" >> cabal.project.local && \
    echo "  extra-lib-dirs: /usr/local/lib" >> cabal.project.local

COPY *.cabal /app/
RUN cabal update && \
    cabal build -j --only-dependencies \
    --extra-include-dirs=/usr/local/include \
    --extra-lib-dirs=/usr/local/lib

COPY . /app
RUN cabal build all -j \
    --extra-include-dirs=/usr/local/include \
    --extra-lib-dirs=/usr/local/lib

CMD ["bash"]