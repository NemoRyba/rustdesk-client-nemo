#!/usr/bin/env bash
cargo ndk --platform 28 --target x86_64-linux-android build --release --features flutter
