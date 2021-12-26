wasm:
	./build_web.sh
	./start_server.sh

build-wasm:
	./build_web.sh

setup-wasm:
	./setup_web.sh

build-ms:
	cross build --release --target x86_64-pc-windows-gnu