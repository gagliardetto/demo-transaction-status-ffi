build-rust-wrapper:
	rm -rf lib
	cargo build --release --lib --target=x86_64-unknown-linux-gnu --target-dir=target
	cbindgen . -o lib/transaction_status.h --lang c
build: build-rust-wrapper
	rm -rf main
	cp target/x86_64-unknown-linux-gnu/release/libdemo_transaction_status_ffi.a lib/libsolana_transaction_status_wrapper.a
	go build main.go
	echo "build done"
