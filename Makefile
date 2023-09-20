ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

build-rust-wrapper-static:
	rm -rf lib
	cargo build --release --lib --target=x86_64-unknown-linux-gnu --target-dir=target
	cbindgen . -o lib/transaction_status.h --lang c
	echo "build-rust-wrapper-static done"
build: build-rust-wrapper-static
	rm -rf main
	cp target/x86_64-unknown-linux-gnu/release/libdemo_transaction_status_ffi.a lib/libsolana_transaction_status_wrapper.a
	go build main.go
	echo "build done"
build-dynamic:
	cp target/x86_64-unknown-linux-gnu/release/libdemo_transaction_status_ffi.so lib/libsolana_transaction_status_wrapper.so
	go build -ldflags="-r $(ROOT_DIR)lib" main.go
