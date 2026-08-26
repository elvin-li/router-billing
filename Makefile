APP        := router-billing
BUILD_DIR  := build
VERSION    := $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
LDFLAGS    := -s -w -X main.version=$(VERSION)
GOFLAGS    := -trimpath -ldflags="$(LDFLAGS)"

.PHONY: all deps arm64 armv7 local pack-arm64 clean fmt vet

all: arm64

deps:
	go mod tidy

fmt:
	gofmt -w .

vet:
	go vet ./...

local:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build $(GOFLAGS) -o $(BUILD_DIR)/$(APP) ./cmd/router-billing

arm64:
	mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build $(GOFLAGS) -o $(BUILD_DIR)/$(APP)-arm64 ./cmd/router-billing

armv7:
	mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build $(GOFLAGS) -o $(BUILD_DIR)/$(APP)-armv7 ./cmd/router-billing

# 打包成可直接 scp 到路由器的 tar
pack-arm64: arm64
	rm -rf $(BUILD_DIR)/pkg && mkdir -p $(BUILD_DIR)/pkg/router-billing
	cp $(BUILD_DIR)/$(APP)-arm64 $(BUILD_DIR)/pkg/router-billing/router-billing
	cp config.example.yaml       $(BUILD_DIR)/pkg/router-billing/
	cp -r web                    $(BUILD_DIR)/pkg/router-billing/
	cp -r deploy/openwrt         $(BUILD_DIR)/pkg/router-billing/
	cp deploy/openwrt/install.sh $(BUILD_DIR)/pkg/router-billing/install.sh
	chmod +x $(BUILD_DIR)/pkg/router-billing/install.sh
	tar -czf $(BUILD_DIR)/router-billing-arm64.tar.gz -C $(BUILD_DIR)/pkg router-billing
	@echo "==> $(BUILD_DIR)/router-billing-arm64.tar.gz"

clean:
	rm -rf $(BUILD_DIR)

# Build an opkg .ipk so a router admin can `opkg install router-billing.ipk`.
# .ipk = ar archive of debian-binary + control.tar.gz + data.tar.gz.
ipk: arm64
	rm -rf $(BUILD_DIR)/ipk && mkdir -p $(BUILD_DIR)/ipk
	# data tree
	install -d $(BUILD_DIR)/ipk/data/usr/bin \
	           $(BUILD_DIR)/ipk/data/etc/router-billing \
	           $(BUILD_DIR)/ipk/data/etc/init.d \
	           $(BUILD_DIR)/ipk/data/etc/uci-defaults \
	           $(BUILD_DIR)/ipk/data/usr/share/router-billing/web/templates \
	           $(BUILD_DIR)/ipk/data/usr/share/router-billing/web/static \
	           $(BUILD_DIR)/ipk/data/var/lib/router-billing
	install -m 0755 $(BUILD_DIR)/$(APP)-arm64 $(BUILD_DIR)/ipk/data/usr/bin/$(APP)
	install -m 0644 config.example.yaml $(BUILD_DIR)/ipk/data/etc/router-billing/config.yaml
	cp -r web/templates/. $(BUILD_DIR)/ipk/data/usr/share/router-billing/web/templates/
	cp -r web/static/.    $(BUILD_DIR)/ipk/data/usr/share/router-billing/web/static/
	install -m 0755 deploy/openwrt/etc/init.d/router-billing $(BUILD_DIR)/ipk/data/etc/init.d/router-billing
	install -m 0755 deploy/openwrt/etc/uci-defaults/99-router-billing-ssid $(BUILD_DIR)/ipk/data/etc/uci-defaults/99-router-billing-ssid
	install -m 0755 deploy/openwrt/usr/share/router-billing/firewall-billing.sh $(BUILD_DIR)/ipk/data/usr/share/router-billing/firewall-billing.sh
	install -m 0755 deploy/openwrt/usr/share/router-billing/setup-secure-ssid.sh $(BUILD_DIR)/ipk/data/usr/share/router-billing/setup-secure-ssid.sh
	install -m 0755 deploy/openwrt/usr/share/router-billing/firewall-shadowsocks.sh $(BUILD_DIR)/ipk/data/usr/share/router-billing/firewall-shadowsocks.sh
	# control tree
	install -d $(BUILD_DIR)/ipk/control
	install -m 0644 deploy/openwrt/ipk/control $(BUILD_DIR)/ipk/control/control
	install -m 0755 deploy/openwrt/ipk/postinst $(BUILD_DIR)/ipk/control/postinst
	install -m 0755 deploy/openwrt/ipk/prerm $(BUILD_DIR)/ipk/control/prerm
	install -m 0644 deploy/openwrt/ipk/conffiles $(BUILD_DIR)/ipk/control/conffiles
	# tarballs
	cd $(BUILD_DIR)/ipk/data && tar -czf ../data.tar.gz --owner=0 --group=0 .
	cd $(BUILD_DIR)/ipk/control && tar -czf ../control.tar.gz --owner=0 --group=0 .
	echo '2.0' > $(BUILD_DIR)/ipk/debian-binary
	# Combine via ar (BSD ar on macOS / GNU ar on linux both work)
	cd $(BUILD_DIR)/ipk && ar -rc ../$(APP)_$(VERSION)_aarch64_generic.ipk debian-binary control.tar.gz data.tar.gz
	@echo "==> $(BUILD_DIR)/$(APP)_$(VERSION)_aarch64_generic.ipk ($$(ls -lh $(BUILD_DIR)/$(APP)_$(VERSION)_aarch64_generic.ipk | awk '{print $$5}'))"
