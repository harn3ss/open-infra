// Self-contained module (stdlib only) for composition-render assertion tests.
// It renders the go-templating inline templates from platform/abstraction/*.yaml
// with a faithful sprig-subset funcmap and asserts on the output — catching
// template-logic regressions (e.g. the hibernation annotation that must ALWAYS
// be set) without needing the Crossplane runtime or the crossplane CLI.
module openinfra/test/render

go 1.26
