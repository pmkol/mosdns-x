module github.com/pmkol/mosdns-x

go 1.25

toolchain go1.25.0

require (
	github.com/Knetic/govaluate v3.0.0+incompatible
	github.com/fsnotify/fsnotify v1.9.0
	github.com/go-redis/redis/v8 v8.11.5
	github.com/go-viper/mapstructure/v2 v2.4.0
	github.com/gobwas/glob v0.2.3
	github.com/golang/snappy v1.0.0
	github.com/google/nftables v0.3.0
	github.com/kardianos/service v1.2.4
	github.com/miekg/dns v1.1.67
	github.com/mitchellh/mapstructure v1.5.0
	github.com/nadoo/ipset v0.5.0
	github.com/pires/go-proxyproto v0.8.1
	github.com/prometheus/client_golang v1.22.0
	github.com/quic-go/quic-go v0.54.0
	github.com/spf13/cobra v1.9.1
	github.com/spf13/viper v1.20.1
	github.com/stretchr/testify v1.10.0
	gitlab.com/go-extension/http v0.0.0-20250719151615-08a618538a4f
	gitlab.com/go-extension/tls v0.0.0-20250722152942-833403b40b08
	go.uber.org/zap v1.27.0
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba
	golang.org/x/exp v0.0.0-20250718183923-645b1fa84792
	golang.org/x/net v0.42.0
	golang.org/x/sync v0.16.0
	golang.org/x/sys v0.34.0
	google.golang.org/protobuf v1.36.6
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/nadoo/ipset v0.5.0 => github.com/IrineSistiana/ipset v0.5.1-0.20220703061533-6e0fc3b04c0a

require (
	github.com/RyuaNerin/go-krypto v1.3.0 // indirect
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/mdlayher/netlink v1.7.3-0.20250113171957-fbb4dce95f42 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/onsi/gomega v1.36.3 // indirect
	github.com/pedroalbanese/camellia v0.0.0-20220911183557-30cc05c20118 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/pmorjan/kmod v1.1.1 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.65.0 // indirect
	github.com/prometheus/procfs v0.17.0 // indirect
	github.com/quic-go/qpack v0.5.1 // indirect
	github.com/sagikazarmark/locafero v0.9.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.14.0 // indirect
	github.com/spf13/cast v1.9.2 // indirect
	github.com/spf13/pflag v1.0.7 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	gitlab.com/go-extension/aes-ccm v0.0.0-20230221065045-e58665ef23c7 // indirect
	gitlab.com/go-extension/hpke v0.0.0-20250212195157-716075a00b8a // indirect
	gitlab.com/go-extension/mlkem768 v0.0.0-20240814071630-937354a2177e // indirect
	gitlab.com/go-extension/rand v0.0.0-20240303103951-707937a049b5 // indirect
	gitlab.com/go-extension/utils v0.0.0-20250718194058-bae8b5a74647 // indirect
	go.uber.org/mock v0.5.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.40.0 // indirect
	golang.org/x/mod v0.26.0 // indirect
	golang.org/x/text v0.27.0 // indirect
	golang.org/x/tools v0.35.0 // indirect
)
