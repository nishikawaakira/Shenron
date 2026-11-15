.PHONY: validate

validate:
	cargo fmt --check
	cargo clippy --locked --all-targets -- -D warnings
	cargo test --locked
