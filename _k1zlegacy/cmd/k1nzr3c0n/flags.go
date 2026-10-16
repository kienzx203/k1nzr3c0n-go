package main

import (
	"flag"
	"net/http"
	"os"
)

func newFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("k1nzr3c0n", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

func fsString(fs *flag.FlagSet, short, long, def, _ string) *string {
	if short != "" {
		return fs.String(short, def, "")
	}
	return fs.String(long, def, "")
}

func fsBool(fs *flag.FlagSet, short, long string, def bool, _ string) *bool {
	if short != "" {
		return fs.Bool(short, def, "")
	}
	return fs.Bool(long, def, "")
}

// fsVarList registers a repeatable string flag; the returned slice accumulates.
func fsVarList(fs *flag.FlagSet, name, _ string) *[]string {
	out := &[]string{}
	fs.Func(name, "", func(s string) error {
		*out = append(*out, s)
		return nil
	})
	return out
}

func listenAndServe(addr string, handler http.Handler) error {
	srv := &http.Server{Addr: addr, Handler: handler}
	return srv.ListenAndServe()
}
