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

If you want to use this repo with official OpenWrt source tree, the following tools and packages need to be added manually:

tools:
- [ucl](https://github.com/coolsnowwolf/lede/tree/master/tools/ucl)
- [upx](https://github.com/coolsnowwolf/lede/tree/master/tools/upx)

packages:
- [dns2socks](https://github.com/immortalwrt/packages/tree/master/net/dns2socks)
- [microsocks](https://github.com/immortalwrt/packages/tree/master/net/microsocks)
- [ipt2socks](https://github.com/immortalwrt/packages/tree/master/net/ipt2socks)
- [pdnsd-alt](https://github.com/immortalwrt/packages/tree/master/net/pdnsd-alt)
- [redsocks2](https://github.com/immortalwrt/packages/tree/master/net/redsocks2)

You may use `svn` to check them out, e.g.:

```bash
mkdir -p package/helloworld
for i in "dns2socks" "microsocks" "ipt2socks" "pdnsd-alt" "redsocks2"; do \
  svn checkout "https://github.com/immortalwrt/packages/trunk/net/$i" "package/helloworld/$i"; \
done
```

You should manually add the following code into tools/Makefile, make sure to add code before the compile command: 

```bash
tools-y += ucl upx
$(curdir)/upx/compile := $(curdir)/ucl/compile
```

e.g.:

```bash
svn checkout https://github.com/coolsnowwolf/lede/trunk/tools/ucl tools/ucl
svn checkout https://github.com/coolsnowwolf/lede/trunk/tools/upx tools/upx

sed -i 'N;24a\tools-y += ucl upx' tools/Makefile
sed -i 'N;40a\$(curdir)/upx/compile := $(curdir)/ucl/compile' tools/Makefile
```
You should note that hard-coding the line number is not an ideal solution. It may destroy the structure of the original file due to the update of the openwrt source code and cause unexpected problems. 
