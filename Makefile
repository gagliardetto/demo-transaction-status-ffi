ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

build-rust-wrapper:
	rm -rf lib
	cargo build --release --lib --target=x86_64-unknown-linux-gnu --target-dir=target
	cbindgen . -o lib/transaction_status.h --lang c
	echo "build-rust-wrapper done"
build-static: build-rust-wrapper
	rm -rf main
	cp target/x86_64-unknown-linux-gnu/release/libdemo_transaction_status_ffi.a lib/libsolana_transaction_status_wrapper.a
	go build main.go
	echo "built static lib and go binary"
build-dynamic: build-rust-wrapper
	rm -rf main
	cp target/x86_64-unknown-linux-gnu/release/libdemo_transaction_status_ffi.so lib/libsolana_transaction_status_wrapper.so
	go build -ldflags="-r $(ROOT_DIR)lib" main.go
	echo "built dynamic lib and go binary"
