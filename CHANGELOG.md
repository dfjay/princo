# Changelog

## [0.4.0](https://github.com/dfjay/princo/compare/v0.3.0...v0.4.0) (2026-10-23)


### ⚠ BREAKING CHANGES

* build every rule set from one fleet-wide rule_data

### Features

* build every rule set from one fleet-wide rule_data ([7a44184](https://github.com/dfjay/princo/commit/7a44184d6b4588af922d6137dac8e1004288ca70))

## [0.3.0](https://github.com/dfjay/princo/compare/v0.2.0...v0.3.0) (2026-10-22)


### ⚠ BREAKING CHANGES

* leave accepting Let's Encrypt's terms to the host
* xray 26.10.21, engines from princo's nixpkgs ([#23](https://github.com/dfjay/princo/issues/23))
* optional Hysteria2 obfuscation, hysteria2 instead of hy2 ([#22](https://github.com/dfjay/princo/issues/22))

### Features

* groups can pick their fastest working node ([aa94234](https://github.com/dfjay/princo/commit/aa94234c4dfb1c1b10f6b2c47e7df2bded41ae70))
* harden the engine's systemd unit ([f26de16](https://github.com/dfjay/princo/commit/f26de161e5eb75809ade0bd9f63d1d26604fc03d))
* leave accepting Let's Encrypt's terms to the host ([f26de16](https://github.com/dfjay/princo/commit/f26de161e5eb75809ade0bd9f63d1d26604fc03d))
* match sniffed protocols in rules ([aa94234](https://github.com/dfjay/princo/commit/aa94234c4dfb1c1b10f6b2c47e7df2bded41ae70))
* optional Hysteria2 obfuscation, hysteria2 instead of hy2 ([#22](https://github.com/dfjay/princo/issues/22)) ([416dcc6](https://github.com/dfjay/princo/commit/416dcc6245000bdc29fd366fb431f8662df29f2c))
* princo init, secret gen and user commands ([#20](https://github.com/dfjay/princo/issues/20)) ([84ef619](https://github.com/dfjay/princo/commit/84ef619279c4152b5ca33828bc7ac5a3c7095b4d))
* sing-box VLESS users carry their names ([aa94234](https://github.com/dfjay/princo/commit/aa94234c4dfb1c1b10f6b2c47e7df2bded41ae70))
* subscriptions name themselves and link to their QR page ([aa94234](https://github.com/dfjay/princo/commit/aa94234c4dfb1c1b10f6b2c47e7df2bded41ae70))
* WARP accounts can set their reserved bytes ([aa94234](https://github.com/dfjay/princo/commit/aa94234c4dfb1c1b10f6b2c47e7df2bded41ae70))
* xray 26.10.21, engines from princo's nixpkgs ([#23](https://github.com/dfjay/princo/issues/23)) ([5168f96](https://github.com/dfjay/princo/commit/5168f96529220d4cc52721b9a3eb4fcddd4aeb58))


### Bug Fixes

* close the ufw ports a node no longer uses ([f26de16](https://github.com/dfjay/princo/commit/f26de161e5eb75809ade0bd9f63d1d26604fc03d))
* engine reads its files by group, nginx logs no subscriptions ([88b0a59](https://github.com/dfjay/princo/commit/88b0a595dd6747cc1477e0415ee4b787fdff7629))
* idle tunnels outlast nginx's 10-minute timeout ([f26de16](https://github.com/dfjay/princo/commit/f26de161e5eb75809ade0bd9f63d1d26604fc03d))
* IP rules match the addresses of domains ([88b0a59](https://github.com/dfjay/princo/commit/88b0a595dd6747cc1477e0415ee4b787fdff7629))
* keep users off sing-box nodes' private networks ([88b0a59](https://github.com/dfjay/princo/commit/88b0a595dd6747cc1477e0415ee4b787fdff7629))
* open the ufw address family the host lacks ([7886228](https://github.com/dfjay/princo/commit/788622897efe2c8a269bff5fd64a7e165ba6b89b))
* profiles drop the Clash API and log only warnings ([aa94234](https://github.com/dfjay/princo/commit/aa94234c4dfb1c1b10f6b2c47e7df2bded41ae70))
* refuse Hysteria2 on a node addressed by IP ([aa94234](https://github.com/dfjay/princo/commit/aa94234c4dfb1c1b10f6b2c47e7df2bded41ae70))
* xray rule sets match their checksums and NixOS's source ([f26de16](https://github.com/dfjay/princo/commit/f26de161e5eb75809ade0bd9f63d1d26604fc03d))

## [0.2.0](https://github.com/dfjay/princo/compare/v0.1.1...v0.2.0) (2026-10-21)


### Features

* pin the engines' versions ([#18](https://github.com/dfjay/princo/issues/18)) ([77fb639](https://github.com/dfjay/princo/commit/77fb6391bc58fef20497105464c136ed6ec8b621))
* princo deploy for Debian and Ubuntu ([#15](https://github.com/dfjay/princo/issues/15)) ([7fd5758](https://github.com/dfjay/princo/commit/7fd57589a2f7a42eb4afd64ca8f0d3fd1f1eaec6))
* xray engine with VLESS over XHTTP ([#17](https://github.com/dfjay/princo/issues/17)) ([1d5e5da](https://github.com/dfjay/princo/commit/1d5e5da65be49e2a2102324b0bbb35fc47968803))

## [0.1.1](https://github.com/dfjay/princo/compare/v0.1.0...v0.1.1) (2026-10-20)


### Bug Fixes

* hidden secret input, refuse vhosts on the mux port, strict names ([#12](https://github.com/dfjay/princo/issues/12)) ([88e03a2](https://github.com/dfjay/princo/commit/88e03a2c4ec6bc4d6bba557d86733f51d582c5e3))

## 0.1.0 (2026-10-19)


### Features

* **config:** princo.yaml schema v1 ([8d5c7b5](https://github.com/dfjay/princo/commit/8d5c7b5d5bdb9451b5b787329d74f6e91dc3244a))
* **fleet:** resolved fleet model with defaults, secrets and validation ([bef0e6e](https://github.com/dfjay/princo/commit/bef0e6e0421a79e18aa184a15236bb5ecdfea26d))
* project skeleton with cobra CLI ([8b7e2a8](https://github.com/dfjay/princo/commit/8b7e2a8ee286f4995194e8154328fff780548191))
* releases, vendored dependencies, config reference ([#8](https://github.com/dfjay/princo/issues/8)) ([796b49c](https://github.com/dfjay/princo/commit/796b49c82eb25bcd75c71f08aed1da6611735451))
* run fleet nodes on NixOS ([#6](https://github.com/dfjay/princo/issues/6)) ([68f5bf5](https://github.com/dfjay/princo/commit/68f5bf5643fcae3e1513ac4bb094bcf80c555587))
* **secrets:** age-encrypted secrets store and princo secret ([c3c178a](https://github.com/dfjay/princo/commit/c3c178ac39a09dfdb5ae2023c58e7721b14de033))
* **secrets:** read secrets from sops files ([ef33406](https://github.com/dfjay/princo/commit/ef33406e57e3908b4459a0f32646c5271bfb7ae5))
* **singbox:** render server configs and client profiles ([d7e091c](https://github.com/dfjay/princo/commit/d7e091c8cdf0ae04071011bc155c7538f42e46e5))
* subscription links per user, plan without a host builder ([#7](https://github.com/dfjay/princo/issues/7)) ([5d4a8c2](https://github.com/dfjay/princo/commit/5d4a8c2d9e41e449fc6234a6a839b8412c178c9c))
* subscription share links and princo render ([8be3a1b](https://github.com/dfjay/princo/commit/8be3a1bb437f20ed0468463a258e0ce4e998d75c))
