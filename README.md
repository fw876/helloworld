## Setup instruction

### Method 1 - Add this repo as a git submodule

- Add new submodule:

  ```bash
  git submodule add --name helloworld https://github.com/fw876/helloworld.git package/helloworld
  ```

- Pull upstream commits:

  ```bash
  git submodule update --remote package/helloworld
  ```

### Method 2 - Add this repo as an OpenWrt feed

- Add new feed:

  ```bash
  sed -i "/helloworld/d" "feeds.conf.default"
  echo "src-git helloworld https://github.com/fw876/helloworld.git" >> "feeds.conf.default"
  ```

- Pull upstream commits:

  ```bash
  ./scripts/feeds update helloworld
  ./scripts/feeds install -a -f -p helloworld
  ```

### Notice

If you want to use this repo with official OpenWrt source tree, the following packages need to be added manually:

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
