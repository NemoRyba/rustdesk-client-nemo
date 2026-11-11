#!/usr/bin/env bash
cargo ndk --platform 28 --target aarch64-linux-android build --release --features flutter,hwcodec
