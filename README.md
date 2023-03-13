## Setup instruction

### Method 1 - Clone this repo directly

1. Clone this repo:

	```bash
	rm -rf package/helloworld
	git clone --depth=1 https://github.com/fw876/helloworld.git package/helloworld
	```

2. Pull upstream commits:

	```bash
	git -C package/helloworld pull
	```

- Remove

  ```bash
  rm -rf package/helloworld
  ```

### Method 2 - Add this repo as a git submodule

1. Add new submodule:

	```bash
	rm -rf package/helloworld
	git submodule add -f --name helloworld https://github.com/fw876/helloworld.git package/helloworld
	```

2. Pull upstream commits:

	```bash
	git submodule update --remote package/helloworld
	```

- Remove

  ```bash
  git submodule deinit -f package/helloworld
  git rm -f package/helloworld
  git reset HEAD .gitmodules
  rm -rf .git/modules{/,/package/}helloworld
  ```

### Method 3 - Add this repo as an OpenWrt feed

1. Add new feed:

	```bash
	sed -i "/helloworld/d" "feeds.conf.default"
	echo "src-git helloworld https://github.com/fw876/helloworld.git" >> "feeds.conf.default"
	```

2. Pull upstream commits:

	```bash
	./scripts/feeds update helloworld
	./scripts/feeds install -a -f -p helloworld
	```

- Remove

  ```bash
  sed -i "/helloworld/d" "feeds.conf.default"
  ./scripts/feeds clean
  ./scripts/feeds update -a
  ./scripts/feeds install -a
  ```

### Note

#### ⚠ For OpenWrt 21.02 or lower version
You have to manually upgrade Golang toolchain to [1.19](https://github.com/openwrt/packages/tree/openwrt-22.03/lang/golang) or higher to compile Xray-core.

e.g.:

```bash
./scripts/feeds update packages
rm -rf feeds/packages/lang/golang
svn co https://github.com/openwrt/packages/branches/openwrt-22.03/lang/golang feeds/packages/lang/golang
```
