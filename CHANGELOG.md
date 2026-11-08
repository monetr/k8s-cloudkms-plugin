# Changelog

## [2.0.0](https://github.com/monetr/k8s-cloudkms-plugin/compare/v1.0.1...v2.0.0) (2026-11-08)


### ⚠ BREAKING CHANGES

* Move the default TPM key handle to 0x81008101

### Features

* Accept a PEM certificate that holds an RSA key ([b36ab9a](https://github.com/monetr/k8s-cloudkms-plugin/commit/b36ab9a55de872da7aaccab88863cc34598724d7))
* Add systemd readiness and watchdog support ([100ae79](https://github.com/monetr/k8s-cloudkms-plugin/commit/100ae79ee8afdb7de3f06f32dd7d309882eaa629))
* Adding support for PCR7 and PCR11 binding ([d25ffdb](https://github.com/monetr/k8s-cloudkms-plugin/commit/d25ffdb4a8ee7837f79eae5c11e019aa5683dcb6))
* Move the default TPM key handle to 0x81008101 ([f1d62aa](https://github.com/monetr/k8s-cloudkms-plugin/commit/f1d62aa974516d573110e0623a2927ec813d8d75))


### Bug Fixes

* Adding tests to cover tpmkey policy things ([98592dd](https://github.com/monetr/k8s-cloudkms-plugin/commit/98592dd81de898e0e7f7b7de54137766acdfae8c))
* Allow disabling the metrics port ([58ac8f3](https://github.com/monetr/k8s-cloudkms-plugin/commit/58ac8f3c9a1e27400e6acd26ef4108598813cc16))
* **deps:** update module google.golang.org/api to v0.310.0 ([#13](https://github.com/monetr/k8s-cloudkms-plugin/issues/13)) ([e0b26db](https://github.com/monetr/k8s-cloudkms-plugin/commit/e0b26dbc5c0115733267a72516131593dc2d0d22))
* **deps:** update module google.golang.org/grpc to v1.85.0 ([#14](https://github.com/monetr/k8s-cloudkms-plugin/issues/14)) ([145d971](https://github.com/monetr/k8s-cloudkms-plugin/commit/145d9717c261177a90c402bdacdc32f06f14d8a0))
* Fixed panic when plugin manager start fails ([b64b934](https://github.com/monetr/k8s-cloudkms-plugin/commit/b64b9344ecd2948a484ef9df7683b0527b7af30a))
* Fixed SIGTERM causing an exit status of 1 ([3fc9733](https://github.com/monetr/k8s-cloudkms-plugin/commit/3fc97332fc4bc0425497183fab4fb7ce50c18298))
* Fixing argument handling ([07dd5e2](https://github.com/monetr/k8s-cloudkms-plugin/commit/07dd5e239a39106f0027bfec837aa7e93793aa9c))
* Fixing timeout refreshing token ([aa34468](https://github.com/monetr/k8s-cloudkms-plugin/commit/aa3446878e7f6170a6a4c5cf3eca28002148536e))
* Improving context passing and adding tests ([f388cc9](https://github.com/monetr/k8s-cloudkms-plugin/commit/f388cc953a23ee4f837aeb28a577b63d9ce2d95f))
* Prevent resetable PCRs from being used ([bb27386](https://github.com/monetr/k8s-cloudkms-plugin/commit/bb27386bc2a36320c8df788e181bb54801ec2590))
* Refuse to create a key if there is no matchin PCR policy ([b624e76](https://github.com/monetr/k8s-cloudkms-plugin/commit/b624e763ead85084d782da7529cebd82e25e60a6))
* Verify the PCR policy signature before persisting ([08fd7c7](https://github.com/monetr/k8s-cloudkms-plugin/commit/08fd7c761dff2cdde677dd6d6b217edf9b4b818f))
* Wait until PCR 11 is ready ([26f5013](https://github.com/monetr/k8s-cloudkms-plugin/commit/26f50132b95a554d0a2fe230a804fadf3ee90be7))


### Miscellaneous

* Adding unit tests for systemd things ([31be012](https://github.com/monetr/k8s-cloudkms-plugin/commit/31be0124cb1d5d1aa797ccf2a3914d2d5282e6b2))
* Even more tests ([ff30e46](https://github.com/monetr/k8s-cloudkms-plugin/commit/ff30e46dc8ceb2647032f72087928c53fb6f059c))


### Documentation

* Clarifying documentation ([9c24fdd](https://github.com/monetr/k8s-cloudkms-plugin/commit/9c24fdda3048b0b0d8b23445d5885d1cf492e63f))
* Updating example to be more concise ([1cc46f0](https://github.com/monetr/k8s-cloudkms-plugin/commit/1cc46f022819cb47c2b9c74ad102f6524f6aa355))

## [1.0.1](https://github.com/monetr/k8s-cloudkms-plugin/compare/v1.0.0...v1.0.1) (2026-10-31)


### Bug Fixes

* **deps:** update module google.golang.org/api to v0.308.0 ([#9](https://github.com/monetr/k8s-cloudkms-plugin/issues/9)) ([38e782b](https://github.com/monetr/k8s-cloudkms-plugin/commit/38e782b88320eb44fd499f262cdecedb9c50c990))
* Go mod tidy on renovate updates ([234bf94](https://github.com/monetr/k8s-cloudkms-plugin/commit/234bf94e3f3972c4f38822da4f5f01e0795648a0))
* Make the health endpoint a unix socket instead ([d297949](https://github.com/monetr/k8s-cloudkms-plugin/commit/d29794930cf3c0d20a5ca4e25db7792c1da3f71e))
* Remove `--integration-test` from prod binary ([cadfa97](https://github.com/monetr/k8s-cloudkms-plugin/commit/cadfa9789701b973ffdccc10179847b7ceed2c62))
* Set a max lifetime of 1 hour ([d3a9223](https://github.com/monetr/k8s-cloudkms-plugin/commit/d3a9223c11f7aff8b6a589284eef0c4d2730f95d))


### Miscellaneous

* Updating README ([a374f22](https://github.com/monetr/k8s-cloudkms-plugin/commit/a374f222273c2e315b52c7b6b99dce2b9ef2a673))

## 1.0.0 (2026-10-31)


### Features

* Adding json loggin ([e7a7c3b](https://github.com/monetr/k8s-cloudkms-plugin/commit/e7a7c3bd922115c6cdc7514572284c6a063c24f3))


### Miscellaneous

* Adding codeql to ci/cd ([c176dcc](https://github.com/monetr/k8s-cloudkms-plugin/commit/c176dcc92cda738ef9da1df258c305b06c19b660))
* Adding release please ([312de01](https://github.com/monetr/k8s-cloudkms-plugin/commit/312de01e144e9978beb7905bb6eb227f97ff510d))
* Adding systemd service example ([660752a](https://github.com/monetr/k8s-cloudkms-plugin/commit/660752acf83fdf4e1fd4d43193645cd9f817f5cb))
* ADding terraform examples ([ac527e7](https://github.com/monetr/k8s-cloudkms-plugin/commit/ac527e722c4360e89640e642999cbabc25b838fc))
* Adding tests and CI ([8a043dd](https://github.com/monetr/k8s-cloudkms-plugin/commit/8a043dd9a22843ca3e50d032021bdbbbfb66407f))
* Adding tpm wrapper ([a31cc0b](https://github.com/monetr/k8s-cloudkms-plugin/commit/a31cc0b4955fd0521266e7aa3fdcf9fc615b0b84))
* Bumping to go 1.27 ([b0ce341](https://github.com/monetr/k8s-cloudkms-plugin/commit/b0ce341fc312773c94878d4768892db5f1ebd991))
* Configure Renovate ([4edcf93](https://github.com/monetr/k8s-cloudkms-plugin/commit/4edcf93635e7678142da25a330b2e3f53c424677))
* **deps:** update actions/attest-build-provenance action to v4.2.2 ([#4](https://github.com/monetr/k8s-cloudkms-plugin/issues/4)) ([a087e1e](https://github.com/monetr/k8s-cloudkms-plugin/commit/a087e1ef2fab1a31297501c21c2da8a7b7c15530))
* **deps:** update actions/checkout action to v7.0.1 ([#3](https://github.com/monetr/k8s-cloudkms-plugin/issues/3)) ([0481d7c](https://github.com/monetr/k8s-cloudkms-plugin/commit/0481d7c453286dd70971ac1ad7e2cbfad271fde8))
* **deps:** update actions/setup-go action to v7 ([#10](https://github.com/monetr/k8s-cloudkms-plugin/issues/10)) ([c21c784](https://github.com/monetr/k8s-cloudkms-plugin/commit/c21c784160d3af56ab79544e270ec637a5a6b5da))
* **deps:** update codecov/codecov-action action to v7.1.1 ([#7](https://github.com/monetr/k8s-cloudkms-plugin/issues/7)) ([cc548e3](https://github.com/monetr/k8s-cloudkms-plugin/commit/cc548e386de49331b9469b3bdcbd87ae444ba672))
* **deps:** update github/codeql-action action to v4.39.1 ([#8](https://github.com/monetr/k8s-cloudkms-plugin/issues/8)) ([bcd826c](https://github.com/monetr/k8s-cloudkms-plugin/commit/bcd826cb90d8f1e1b149e3be9b78a9cf18fb21f8))
