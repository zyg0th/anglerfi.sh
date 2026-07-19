.PHONY: build install uninstall clean

build:
	./build-deb.sh

install: build
	sudo apt install -y "$$(ls -t dist/*.deb | head -1)"

uninstall:
	sudo apt remove -y anglerfish

clean:
	rm -rf build dist
